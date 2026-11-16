"""Validate the live ChatGPT CIMD document with the local FastMCP provider.

Only requests public ChatGPT client metadata, does not authorize any user or
execute tools, and uses a disposable test passphrase.
"""
from __future__ import annotations

import modal

app = modal.App("modal-sandbox-chatgpt-cimd-smoke")
image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "fastmcp>=3.4,<3.5", "httpx>=0.27,<1"
).add_local_python_source("oauth_support").add_local_python_source("passphrase_oauth")


@app.function(image=image, timeout=180)
def smoke():
    import asyncio
    import base64
    import hashlib
    import secrets
    import tempfile
    from pathlib import Path
    from urllib.parse import urlparse

    import httpx
    from fastmcp import FastMCP
    from passphrase_oauth import BASE_URL, PassphraseOAuthProvider

    async def execute():
        with tempfile.TemporaryDirectory() as directory:
            provider = PassphraseOAuthProvider(
                secrets.token_urlsafe(48), state_file=Path(directory) / "state.enc",
                volume_commit=False,
            )
            client_id = "https://chatgpt.com/oauth/client.json"
            client = await provider.get_client(client_id)
            assert client is not None, "ChatGPT CIMD document could not be validated"
            document = client.cimd_document
            assert document is not None
            assert str(document.client_id) == client_id
            assert client.token_endpoint_auth_method == "none"
            assert document.redirect_uris, "No CIMD redirect URI"
            callback = document.redirect_uris[0]
            assert urlparse(callback).hostname == "chatgpt.com"
            print("Live ChatGPT CIMD fetched and validated:", client_id)
            print("Registered callback hostname: chatgpt.com")

            server = FastMCP("CIMD test only", auth=provider)
            @server.custom_route("/consent", methods=["GET", "POST"])
            async def consent(request):
                return await provider.consent(request)

            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=server.http_app(stateless_http=True)),
                base_url=BASE_URL, timeout=90, follow_redirects=False,
            ) as http:
                response = await http.get("/authorize", params={
                    "client_id": client_id, "redirect_uri": callback,
                    "response_type": "code", "scope": "sandbox",
                    "code_challenge": challenge, "code_challenge_method": "S256",
                    "state": "cimd-test", "resource": BASE_URL.rstrip("/") + "/mcp",
                })
                assert response.status_code == 302, (
                    response.status_code, response.text[:1300]
                )
                assert response.headers["location"].startswith(BASE_URL.rstrip("/") + "/consent?")
                print("Live ChatGPT CIMD authorization reaches local consent page")
            return True

    return asyncio.run(execute())


@app.local_entrypoint()
def main():
    assert smoke.remote()
    print("PASS ChatGPT CIMD protocol smoke")
