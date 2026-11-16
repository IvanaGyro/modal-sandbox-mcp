"""End-to-end single-user OAuth 2.1 test using an isolated in-process ASGI app.

Exercises DCR, authorization code + S256 PKCE, passphrase consent, token exchange,
scope/resource validation, wrong password, token replay, and encrypted recovery.
No production credential is used and no public shell is exposed.
"""

from __future__ import annotations

import modal

app = modal.App("modal-sandbox-mcp-passphrase-oauth-smoke")
image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "fastmcp>=3.4,<3.5", "httpx>=0.27,<1"
).add_local_python_source("oauth_support").add_local_python_source("passphrase_oauth")


@app.function(image=image, timeout=180)
def smoke() -> dict:
    import asyncio
    import base64
    import hashlib
    import os
    from pathlib import Path
    import secrets
    import tempfile
    from urllib.parse import parse_qs, urlparse

    import httpx
    from fastmcp import FastMCP
    from passphrase_oauth import BASE_URL, PassphraseOAuthProvider, SCOPE

    async def test():
        password = secrets.token_urlsafe(48)
        with tempfile.TemporaryDirectory(prefix="oauth-passphrase-") as directory:
            path = Path(directory) / "state.enc"
            provider = PassphraseOAuthProvider(password, state_file=path,
                                                volume_commit=False)
            server = FastMCP("OAuth Test Only", auth=provider)

            @server.custom_route("/consent", methods=["GET", "POST"])
            async def consent(request):
                return await provider.consent(request)

            asgi = server.http_app(stateless_http=True)
            transport = httpx.ASGITransport(app=asgi)
            redirect = "https://chatgpt.com/connector_platform_oauth_redirect"
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            resource = BASE_URL.rstrip("/") + "/mcp"

            async with httpx.AsyncClient(
                transport=transport, base_url=BASE_URL,
                follow_redirects=False, timeout=60,
            ) as client:
                metadata = await client.get("/.well-known/oauth-authorization-server")
                metadata.raise_for_status()
                info = metadata.json()
                assert "S256" in info["code_challenge_methods_supported"], info
                assert info["client_id_metadata_document_supported"] is True
                assert "none" in info["token_endpoint_auth_methods_supported"]
                print("Discovery: S256, CIMD, public-client PKCE OK")

                reg = await client.post("/register", json={
                    "client_name": "ChatGPT protocol test",
                    "redirect_uris": [redirect],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                    "scope": SCOPE,
                })
                assert reg.status_code in (200, 201), (reg.status_code, reg.text[:1500])
                client_id = reg.json()["client_id"]
                print("Dynamic client registration: OK")

                params = {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "test-state",
                    "scope": SCOPE,
                    "resource": resource,
                }
                auth = await client.get("/authorize", params=params)
                assert auth.status_code == 302, (auth.status_code, auth.text[:1500])
                consent_url = auth.headers["location"]
                assert consent_url.startswith(BASE_URL.rstrip("/") + "/consent?")
                query = parse_qs(urlparse(consent_url).query)
                handle = query["handle"][0]
                csrf = query["csrf"][0]
                screen = await client.get(consent_url)
                assert screen.status_code == 200
                assert "Passphrase" in screen.text or "passphrase" in screen.text
                assert "modal_oauth_csrf" in screen.cookies or "modal_oauth_csrf" in client.cookies

                bad = await client.post("/consent", data={
                    "handle": handle, "csrf": csrf,
                    "passphrase": "invalid-passphrase", "decision": "approve",
                })
                assert bad.status_code == 403
                print("Consent: invalid passphrase rejected")

                approved = await client.post("/consent", data={
                    "handle": handle, "csrf": csrf,
                    "passphrase": password, "decision": "approve",
                })
                assert approved.status_code == 303, (approved.status_code, approved.text[:1500])
                callback = urlparse(approved.headers["location"])
                assert callback.hostname == "chatgpt.com"
                returned = parse_qs(callback.query)
                assert returned["state"] == ["test-state"]
                code = returned["code"][0]
                print("Consent: correct passphrase creates one-use code")

                token_request = {
                    "grant_type": "authorization_code",
                    "client_id": client_id, "code": code,
                    "code_verifier": verifier, "redirect_uri": redirect,
                    "resource": resource,
                }
                issued = await client.post("/token", data=token_request)
                assert issued.status_code == 200, (issued.status_code, issued.text[:2000])
                tokens = issued.json()
                access_token = tokens["access_token"]
                refresh_token = tokens["refresh_token"]
                assert (await provider.verify_token(access_token)).subject == "modal-sandbox-owner"
                assert (await provider.verify_token(access_token)).resource == resource
                print("Token: exchange with S256 PKCE and resource binding OK")

                replay = await client.post("/token", data=token_request)
                assert replay.status_code in (400, 401), (replay.status_code, replay.text[:1000])
                print("Token: authorization-code replay rejected")

                # Credential store must remain valid across service restarts.
                restored = PassphraseOAuthProvider(password, state_file=path,
                                                   volume_commit=False)
                assert (await restored.verify_token(access_token)) is not None
                print("Encrypted OAuth token state survives fresh instance")

                renew = await client.post("/token", data={
                    "grant_type": "refresh_token", "client_id": client_id,
                    "refresh_token": refresh_token, "resource": resource,
                })
                assert renew.status_code == 200, (renew.status_code, renew.text[:1500])
                new_access = renew.json()["access_token"]
                assert (await provider.verify_token(new_access)) is not None
                assert (await provider.verify_token(access_token)) is None
                print("Refresh: old tokens revoked, new tokens accepted")
            return {"dcr": "pass", "pkce": "pass", "consent": "pass",
                    "persistence": "pass", "refresh": "pass"}

    return asyncio.run(test())


@app.local_entrypoint()
def main():
    result = smoke.remote()
    print("PASS self-hosted OAuth test:", result)
