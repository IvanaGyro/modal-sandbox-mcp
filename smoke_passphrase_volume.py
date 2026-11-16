"""Verify encrypted OAuth state survives actual Modal Volume commits and fresh containers."""
from __future__ import annotations
import modal

app = modal.App("modal-sandbox-oauth-volume-smoke")
volume = modal.Volume.from_name("modal-sandbox-mcp-oauth-volume-smoke", create_if_missing=True)
image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "fastmcp>=3.4,<3.5"
).add_local_python_source("oauth_support").add_local_python_source("passphrase_oauth")

STATE = "/oauth-state/test-state.enc"


@app.function(image=image, volumes={"/oauth-state": volume}, timeout=120)
def create_state(password: str, value: str) -> None:
    import asyncio
    import time
    from pathlib import Path
    import passphrase_oauth
    passphrase_oauth.AUTH_VOLUME = volume
    p = passphrase_oauth.PassphraseOAuthProvider(
        password, state_file=Path(STATE), volume_commit=True,
    )
    p._pending["volume-write-test"] = {
        "client_id": "test",
        "params": {},
        "expires_at": time.time() + 600,
        "csrf_hash": value,
        "attempts": 0,
    }
    asyncio.run(p._persist())
    print("Encrypted state written and Modal Volume committed")


@app.function(image=image, volumes={"/oauth-state": volume}, timeout=120)
def verify_state(password: str, value: str) -> None:
    import asyncio
    from pathlib import Path
    import passphrase_oauth
    passphrase_oauth.AUTH_VOLUME = volume
    p = passphrase_oauth.PassphraseOAuthProvider(
        password, state_file=Path(STATE), volume_commit=True,
    )
    assert p._pending["volume-write-test"]["csrf_hash"] == value
    Path(STATE).unlink()
    asyncio.run(volume.commit.aio())
    print("Encrypted state recovered in a second Modal function; test file removed")


@app.local_entrypoint()
def main():
    import secrets
    password = secrets.token_urlsafe(48)
    marker = secrets.token_hex(20)
    create_state.remote(password, marker)
    verify_state.remote(password, marker)
    print("PASS actual Modal Volume commit and cross-container recovery")
