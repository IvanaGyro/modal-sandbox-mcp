"""GitHub OAuth with encrypted, durable Modal storage."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import modal

BASE_URL = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run"
AUTH_VOLUME = modal.Volume.from_name("modal-sandbox-mcp-oauth-state", create_if_missing=True)


class CommitOnWriteStore:
    """AsyncKeyValue proxy that commits each OAuth state write to the Volume."""

    def __init__(self, store):
        self.store = store

    async def get(self, key, collection=None):
        return await self.store.get(key, collection=collection)

    async def get_many(self, keys, collection=None):
        return await self.store.get_many(keys, collection=collection)

    async def ttl(self, key, collection=None):
        return await self.store.ttl(key, collection=collection)

    async def ttl_many(self, keys, collection=None):
        return await self.store.ttl_many(keys, collection=collection)

    async def put(self, key, value, collection=None, ttl=None):
        await self.store.put(key, value, collection=collection, ttl=ttl)
        await AUTH_VOLUME.commit.aio()

    async def put_many(self, keys, values, collection=None, ttl=None):
        await self.store.put_many(keys, values, collection=collection, ttl=ttl)
        await AUTH_VOLUME.commit.aio()

    async def delete(self, key, collection=None):
        result = await self.store.delete(key, collection=collection)
        await AUTH_VOLUME.commit.aio()
        return result

    async def delete_many(self, keys, collection=None):
        result = await self.store.delete_many(keys, collection=collection)
        await AUTH_VOLUME.commit.aio()
        return result


def github_oauth():
    from cryptography.fernet import Fernet
    from fastmcp.server.auth.providers.github import GitHubProvider
    from key_value.aio.stores.filetree import (
        FileTreeStore, FileTreeV1CollectionSanitizationStrategy,
        FileTreeV1KeySanitizationStrategy,
    )
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    required = ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "MCP_OAUTH_SIGNING_KEY"]
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError("Missing GitHub OAuth settings: " + ", ".join(missing))
    signing_key = os.environ["MCP_OAUTH_SIGNING_KEY"]
    if len(signing_key) < 32:
        raise RuntimeError("MCP_OAUTH_SIGNING_KEY must be at least 32 characters")

    root = Path("/oauth-state/clients")
    root.mkdir(parents=True, exist_ok=True)
    store = FileTreeStore(
        data_directory=root,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(root),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(root),
    )
    encryption_key = base64.urlsafe_b64encode(
        hashlib.sha256(("modal-mcp-storage-v1:" + signing_key).encode()).digest()
    )
    return GitHubProvider(
        client_id=os.environ["GITHUB_CLIENT_ID"],
        client_secret=os.environ["GITHUB_CLIENT_SECRET"],
        base_url=os.getenv("MCP_BASE_URL", BASE_URL),
        jwt_signing_key=signing_key,
        client_storage=FernetEncryptionWrapper(
            key_value=CommitOnWriteStore(store),
            fernet=Fernet(encryption_key),
        ),
    )


def require_authorized_owner() -> None:
    """Authorize the designated GitHub identity for *every* sandbox tool."""
    mode = os.getenv("MCP_AUTH_MODE", "").lower().strip()
    if mode == "static-dev":
        return  # FastMCP has verified the private bearer token.
    from fastmcp.server.dependencies import get_access_token
    token = get_access_token()
    if token is None:
        raise PermissionError("Missing authorized identity")
    claims = token.claims or {}
    if mode == "passphrase":
        from passphrase_oauth import SCOPE, RESOURCE
        if token.subject != "modal-sandbox-owner" or token.resource != RESOURCE or SCOPE not in token.scopes:
            raise PermissionError("OAuth token does not grant owner sandbox access")
    elif mode == "github":
        expected = os.getenv("MCP_GITHUB_ALLOWED_LOGIN", "IvanaGyro")
        if str(claims.get("login", "")).casefold() != expected.casefold():
            raise PermissionError("This GitHub account cannot execute sandbox commands")
    elif mode == "oauth":
        expected_sub = os.getenv("MCP_ALLOWED_SUB")
        if not expected_sub or claims.get("sub") != expected_sub:
            raise PermissionError("This OAuth subject cannot execute sandbox commands")
    else:
        raise PermissionError("Unknown authentication mode")
