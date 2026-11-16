"""Self-hosted, single-owner OAuth 2.1 provider for ChatGPT -> Modal MCP.

The MCP SDK supplies S256 PKCE validation, client registration, authorization
code and refresh-token exchanges. This module adds explicit user consent,
a separate passphrase, CIMD validation, and encrypted durable state.

This is intended for a private, single-user experimental server. It is not
a general-purpose identity provider or a multi-tenant OAuth implementation.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import parse_qs, urlparse, urlsplit

from cryptography.fernet import Fernet, InvalidToken
from fastmcp.server.auth.cimd import CIMDClientManager
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
    RefreshToken, construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from oauth_support import AUTH_VOLUME, BASE_URL

RESOURCE = BASE_URL.rstrip("/") + "/mcp"
SCOPE = "sandbox"
AUTH_CODE_TTL_SECONDS = 300
CONSENT_TTL_SECONDS = 300
REFRESH_TTL_SECONDS = 30 * 24 * 3600
MAX_FAILED_PASSPHRASES = 5
STATE_FILE = Path(os.getenv("MCP_OAUTH_DATA_FILE", "/oauth-state/passphrase-state.enc"))


def _safe_chatgpt_cimd(client_id: str) -> bool:
    parsed = urlsplit(client_id)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "chatgpt.com"
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and parsed.path.startswith("/oauth/")
        and parsed.path.endswith("/client.json")
    )


def _chatgpt_callback(uri: str) -> bool:
    parsed = urlsplit(uri)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "chatgpt.com"
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )


class PassphraseOAuthProvider(InMemoryOAuthProvider):
    """OAuth Authorization Server with explicit user consent and disk recovery."""

    def __init__(
        self,
        passphrase: str,
        *,
        base_url: str = BASE_URL,
        state_file: Path | None = None,
        volume_commit: bool = True,
        allowed_redirect_hosts: frozenset[str] = frozenset({"chatgpt.com"}),
    ) -> None:
        if len(passphrase) < 32:
            raise ValueError("MCP_AUTH_PASSPHRASE needs at least 32 characters")
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[SCOPE],
                default_scopes=[SCOPE],
                client_secret_expiry_seconds=None,
            ),
            required_scopes=[SCOPE],
        )
        self.resource = base_url.rstrip("/") + "/mcp"
        self.owner_subject = "modal-sandbox-owner"
        self._passphrase_digest = hashlib.sha256(passphrase.encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(
            hashlib.sha256(("modal-selfhosted-oauth-state-v1:" + passphrase).encode()).digest()
        ))
        self._state_file = state_file or STATE_FILE
        self._volume_commit = volume_commit
        self._redirect_hosts = allowed_redirect_hosts
        self._lock = asyncio.Lock()
        self._pending: dict[str, dict] = {}
        self._cimd = CIMDClientManager(
            enable_cimd=True,
            default_scope=SCOPE,
        )
        self._restore()

    def _snapshot(self) -> dict:
        return {
            "schema": 1,
            "clients": {k: v.model_dump(mode="json") for k, v in self.clients.items()},
            "auth_codes": {k: v.model_dump(mode="json") for k, v in self.auth_codes.items()},
            "access_tokens": {k: v.model_dump(mode="json") for k, v in self.access_tokens.items()},
            "refresh_tokens": {k: v.model_dump(mode="json") for k, v in self.refresh_tokens.items()},
            "a2r": self._access_to_refresh_map,
            "r2a": self._refresh_to_access_map,
            "pending": self._pending,
        }

    def _restore(self) -> None:
        if not self._state_file.exists():
            return
        try:
            data = json.loads(self._fernet.decrypt(self._state_file.read_bytes()))
        except (InvalidToken, ValueError, OSError) as exc:
            raise RuntimeError(
                "OAuth state cannot be decrypted. Restore the previous passphrase "
                "or deliberately reset the Modal OAuth state volume."
            ) from exc
        if data.get("schema") != 1:
            raise RuntimeError("Unsupported stored OAuth state schema")
        now = time.time()
        self.clients = {
            k: OAuthClientInformationFull.model_validate(v)
            for k, v in data.get("clients", {}).items()
        }
        self.auth_codes = {
            k: AuthorizationCode.model_validate(v)
            for k, v in data.get("auth_codes", {}).items()
            if v["expires_at"] > now
        }
        self.access_tokens = {
            k: AccessToken.model_validate(v)
            for k, v in data.get("access_tokens", {}).items()
            if v.get("expires_at") is None or v["expires_at"] > now
        }
        self.refresh_tokens = {
            k: RefreshToken.model_validate(v)
            for k, v in data.get("refresh_tokens", {}).items()
            if v.get("expires_at") is None or v["expires_at"] > now
        }
        self._access_to_refresh_map = {
            k: v for k, v in data.get("a2r", {}).items()
            if k in self.access_tokens and v in self.refresh_tokens
        }
        self._refresh_to_access_map = {
            k: v for k, v in data.get("r2a", {}).items()
            if k in self.refresh_tokens and v in self.access_tokens
        }
        self._pending = {
            k: v for k, v in data.get("pending", {}).items()
            if v.get("expires_at", 0) > now
        }

    async def _persist(self) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(self._snapshot(), separators=(",", ":")).encode()
        ciphertext = self._fernet.encrypt(raw)
        tmp = self._state_file.with_name(
            self._state_file.name + "." + secrets.token_hex(8) + ".tmp"
        )
        try:
            with open(tmp, "xb") as file:
                os.fchmod(file.fileno(), 0o600)
                file.write(ciphertext)
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp, self._state_file)
            if self._volume_commit:
                await AUTH_VOLUME.commit.aio()
        finally:
            tmp.unlink(missing_ok=True)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if _safe_chatgpt_cimd(client_id):
            client = await self._cimd.get_client(client_id)
            if client is None:
                return None
            # ChatGPT supports both public PKCE and private-key JWT. Prefer
            # the public PKCE option, which the SDK's token handler supports.
            client.token_endpoint_auth_method = "none"
            client.scope = SCOPE
            return client
        return await super().get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # Do not offer password-entry consent to arbitrary DCR redirects.
        if not client_info.redirect_uris or not all(
            urlsplit(str(uri)).hostname in self._redirect_hosts
            and _chatgpt_callback(str(uri))
            for uri in client_info.redirect_uris
        ):
            raise ValueError("Only HTTPS chatgpt.com redirect URIs are accepted")
        async with self._lock:
            await super().register_client(client_info)
            await self._persist()

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if client.client_id is None:
            raise AuthorizeError("unauthorized_client", "Client identity required")
        if not _chatgpt_callback(str(params.redirect_uri)):
            raise AuthorizeError("invalid_request", "Only ChatGPT redirect URIs are allowed")
        if params.resource is not None and params.resource.rstrip("/") != self.resource:
            raise AuthorizeError("invalid_target", "Unexpected MCP resource")
        if SCOPE not in (params.scopes or []):
            raise AuthorizeError("invalid_scope", "Sandbox scope is required")
        handle = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        async with self._lock:
            self._pending[handle] = {
                "client_id": client.client_id,
                "params": params.model_dump(mode="json"),
                "csrf_hash": hashlib.sha256(csrf.encode()).hexdigest(),
                "expires_at": time.time() + CONSENT_TTL_SECONDS,
                "attempts": 0,
            }
            await self._persist()
        # Callback URL remains a server-local fixed URL, not an untrusted one.
        return str(self.base_url).rstrip("/") + "/consent?handle=" + handle + "&csrf=" + csrf

    async def consent(self, request: Request):
        if request.method == "GET":
            handle = request.query_params.get("handle", "")
            csrf = request.query_params.get("csrf", "")
            pending = self._pending.get(handle)
            if not pending or pending.get("expires_at", 0) <= time.time():
                return HTMLResponse("Authorization request expired", status_code=400)
            if not hmac.compare_digest(
                pending["csrf_hash"], hashlib.sha256(csrf.encode()).hexdigest()
            ):
                return HTMLResponse("Invalid authorization request", status_code=400)
            client_id = html.escape(pending["client_id"])
            form = (
                '<!doctype html><html lang="en"><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<meta name="referrer" content="no-referrer">'
                '<title>Authorize Modal MCP</title>'
                '<style>body{font:16px system-ui;max-width:36rem;margin:3rem auto;'
                'padding:1rem;line-height:1.5}input{padding:.7rem;width:100%;'
                'box-sizing:border-box}button{padding:.7rem;margin:.8rem .5rem 0 0}</style>'
                '<h1>Authorize Modal Sandbox MCP</h1>'
                '<p>This grants the requesting ChatGPT client remote Linux shell '
                'and file write access. Only authorize if you initiated the connection.</p>'
                '<p>Client ID: <code>' + client_id + '</code></p>'
                '<form method="post" action="/consent">'
                '<input type="hidden" name="handle" value="' + html.escape(handle) + '">'
                '<input type="hidden" name="csrf" value="' + html.escape(csrf) + '">'
                '<label>Private passphrase<input type="password" name="passphrase" '
                'required autocomplete="off"></label>'
                '<button name="decision" value="approve">Authorize</button>'
                '<button name="decision" value="deny" formnovalidate>Cancel</button>'
                '</form></html>'
            )
            response = HTMLResponse(form, headers={
                "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
                "X-Content-Type-Options": "nosniff",
            })
            response.set_cookie(
                "modal_oauth_csrf", csrf, secure=True, httponly=True,
                samesite="lax", max_age=CONSENT_TTL_SECONDS, path="/consent"
            )
            return response

        form = await request.form()
        handle = str(form.get("handle", ""))
        csrf = str(form.get("csrf", ""))
        supplied = str(form.get("passphrase", ""))
        decision = str(form.get("decision", ""))
        cookie_csrf = request.cookies.get("modal_oauth_csrf", "")
        if (
            not handle or not csrf or not cookie_csrf
            or not hmac.compare_digest(csrf, cookie_csrf)
        ):
            return HTMLResponse("Invalid consent session", status_code=403)
        async with self._lock:
            pending = self._pending.get(handle)
            if not pending or pending["expires_at"] <= time.time():
                return HTMLResponse("Authorization request expired", status_code=400)
            if not hmac.compare_digest(
                pending["csrf_hash"], hashlib.sha256(csrf.encode()).hexdigest()
            ):
                return HTMLResponse("Invalid consent session", status_code=403)
            if pending["attempts"] >= MAX_FAILED_PASSPHRASES:
                return HTMLResponse("Too many attempts", status_code=429)
            params = AuthorizationParams.model_validate(pending["params"])
            if decision == "deny":
                del self._pending[handle]
                await self._persist()
                return RedirectResponse(
                    construct_redirect_uri(str(params.redirect_uri),
                                           error="access_denied", state=params.state),
                    status_code=303,
                )
            if decision != "approve" or not hmac.compare_digest(
                hashlib.sha256(supplied.encode()).digest(), self._passphrase_digest
            ):
                pending["attempts"] += 1
                await self._persist()
                return HTMLResponse("Invalid passphrase or decision", status_code=403)

            client = await self.get_client(pending["client_id"])
            if client is None:
                return HTMLResponse("Client no longer valid", status_code=400)
            # InMemoryOAuthProvider requires authorization clients to be
            # registered. CIMD clients are validated by the CIMD manager, so
            # only register them temporarily during the code-generation call.
            cimd = _safe_chatgpt_cimd(pending["client_id"])
            if cimd:
                self.clients[client.client_id] = client
            try:
                redirect = await super().authorize(client, params)
            finally:
                if cimd:
                    self.clients.pop(client.client_id, None)
            code = parse_qs(urlparse(redirect).query).get("code", [None])[0]
            if not code or code not in self.auth_codes:
                raise RuntimeError("Failed to create authorization code")
            self.auth_codes[code].resource = self.resource
            self.auth_codes[code].subject = self.owner_subject
            del self._pending[handle]
            await self._persist()
        response = RedirectResponse(redirect, status_code=303,
                                    headers={"Cache-Control": "no-store"})
        response.delete_cookie("modal_oauth_csrf", path="/consent")
        return response

    async def exchange_authorization_code(self, client, authorization_code):
        async with self._lock:
            result = await super().exchange_authorization_code(client, authorization_code)
            access = self.access_tokens[result.access_token]
            access.resource = self.resource
            access.subject = self.owner_subject
            access.claims = {"sub": self.owner_subject, "iss": str(self.base_url).rstrip("/")}
            refresh = self.refresh_tokens[result.refresh_token]
            refresh.resource = self.resource
            refresh.subject = self.owner_subject
            refresh.expires_at = int(time.time() + REFRESH_TTL_SECONDS)
            await self._persist()
            return result

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        if refresh_token.resource != self.resource or refresh_token.subject != self.owner_subject:
            raise ValueError("Invalid refresh token resource or owner")
        async with self._lock:
            result = await super().exchange_refresh_token(client, refresh_token, scopes)
            self.access_tokens[result.access_token].resource = self.resource
            self.access_tokens[result.access_token].subject = self.owner_subject
            self.access_tokens[result.access_token].claims = {
                "sub": self.owner_subject, "iss": str(self.base_url).rstrip("/")
            }
            self.refresh_tokens[result.refresh_token].resource = self.resource
            self.refresh_tokens[result.refresh_token].subject = self.owner_subject
            self.refresh_tokens[result.refresh_token].expires_at = int(
                time.time() + REFRESH_TTL_SECONDS
            )
            await self._persist()
            return result

    async def revoke_token(self, token: AccessToken | RefreshToken):
        async with self._lock:
            await super().revoke_token(token)
            await self._persist()

    async def verify_token(self, token: str) -> AccessToken | None:
        verified = await super().verify_token(token)
        if (
            verified is None
            or verified.resource != self.resource
            or verified.subject != self.owner_subject
            or SCOPE not in verified.scopes
        ):
            return None
        return verified

    def get_routes(self, mcp_path=None):
        routes = super().get_routes(mcp_path)
        # Advertise the public PKCE method and CIMD, which ChatGPT supports.
        # The MCP SDK's standard metadata generator otherwise advertises only
        # confidential OAuth clients, despite accepting public PKCE clients.
        updated = []
        for route in routes:
            if route.path == "/.well-known/oauth-authorization-server":
                async def metadata(_request):
                    origin = str(self.base_url).rstrip("/")
                    return JSONResponse({
                        "issuer": origin,
                        "authorization_endpoint": origin + "/authorize",
                        "token_endpoint": origin + "/token",
                        "registration_endpoint": origin + "/register",
                        "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code", "refresh_token"],
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": [
                            "none", "client_secret_post", "client_secret_basic"
                        ],
                        "client_id_metadata_document_supported": True,
                        "scopes_supported": [SCOPE],
                    }, headers={"Cache-Control": "no-store"})
                updated.append(Route(route.path, endpoint=metadata, methods=["GET"]))
            else:
                updated.append(route)
        return updated
