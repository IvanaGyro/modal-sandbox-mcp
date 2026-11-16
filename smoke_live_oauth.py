"""Live OAuth -> MCP protocol and sandbox lifecycle test.

Uses the existing Modal Secret only inside a Modal Function. No token,
passphrase, code, refresh token or Authorization header is logged.
A created Sandbox is terminated in a finally block.
"""
from __future__ import annotations
import modal

app = modal.App("modal-sandbox-live-selfhosted-oauth-smoke")
image = modal.Image.debian_slim(python_version="3.12").pip_install("httpx>=0.27,<1")
ORIGIN = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run"
MCP = ORIGIN + "/mcp"
CIMD_ID = "https://chatgpt.com/oauth/client.json"


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("modal-mcp-auth")],
    timeout=240,
)
def verify_live_oauth() -> dict:
    import base64
    import hashlib
    import json
    import os
    import secrets
    from urllib.parse import parse_qs, urlparse

    import httpx

    secret = os.getenv("MCP_AUTH_PASSPHRASE") or os.getenv("MCP_DEV_BEARER_TOKEN")
    if not secret or len(secret) < 32:
        raise RuntimeError("The Modal secret lacks a valid OAuth passphrase")

    def decode(resp: httpx.Response) -> dict:
        resp.raise_for_status()
        if "text/event-stream" in resp.headers.get("content-type", ""):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    item = json.loads(line[5:].strip())
                    if "result" in item or "error" in item:
                        return item
            raise RuntimeError("SSE frame missing a JSON-RPC result")
        return resp.json()

    sandbox_id = None
    with httpx.Client(timeout=90, follow_redirects=False) as web_client:
        doc = web_client.get(CIMD_ID)
        doc.raise_for_status()
        callback = doc.json()["redirect_uris"][0]
        assert urlparse(callback).hostname == "chatgpt.com"

        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        auth = web_client.get(ORIGIN + "/authorize", params={
            "response_type": "code",
            "client_id": CIMD_ID,
            "redirect_uri": callback,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "sandbox",
            "state": "live-verify",
            "resource": MCP,
        })
        assert auth.status_code == 302, (
            "Authorization endpoint error: HTTP " + str(auth.status_code)
        )
        consent_url = auth.headers["location"]
        assert consent_url.startswith(ORIGIN + "/consent?")
        query = parse_qs(urlparse(consent_url).query)
        view = web_client.get(consent_url)
        assert view.status_code == 200, "Could not load consent page"
        authn = web_client.post(ORIGIN + "/consent", data={
            "handle": query["handle"][0],
            "csrf": query["csrf"][0],
            "passphrase": secret,
            "decision": "approve",
        })
        assert authn.status_code == 303, (
            "Consent error: HTTP " + str(authn.status_code)
        )
        callback_uri = urlparse(authn.headers["location"])
        assert callback_uri.hostname == "chatgpt.com"
        code = parse_qs(callback_uri.query)["code"][0]

        issued = web_client.post(ORIGIN + "/token", data={
            "grant_type": "authorization_code",
            "client_id": CIMD_ID,
            "code": code,
            "redirect_uri": callback,
            "code_verifier": verifier,
            "resource": MCP,
        })
        assert issued.status_code == 200, (
            "Token endpoint error: HTTP " + str(issued.status_code)
        )
        access_token = issued.json()["access_token"]
        print("Live ChatGPT CIMD -> consent -> S256 token exchange: OK")

        headers = {
            "Authorization": "Bearer " + access_token,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-06-18",
        }
        with httpx.Client(headers=headers, timeout=90) as mcp_client:
            init = decode(mcp_client.post(MCP, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "modal-live-oauth-test", "version": "1"},
                },
            }))
            assert init.get("result"), "MCP initialize failed"
            mcp_client.post(MCP, json={
                "jsonrpc": "2.0", "method": "notifications/initialized"
            }).raise_for_status()
            tools = decode(mcp_client.post(MCP, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
            }))
            names = {x["name"] for x in tools["result"]["tools"]}
            assert {
                "create_sandbox", "exec_command", "read_path", "write_file",
                "sandbox_status", "terminate_sandbox"
            }.issubset(names), names
            print("Live OAuth authenticated initialize and tools/list: required tools OK")

            seq = 10
            def tool(name: str, args: dict) -> dict:
                nonlocal seq
                seq += 1
                response = decode(mcp_client.post(MCP, json={
                    "jsonrpc": "2.0", "id": seq, "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                }))
                assert "error" not in response, name + " JSON-RPC error"
                result = response["result"]
                assert not result.get("isError"), name + " returned a tool error"
                contents = result.get("structuredContent")
                if isinstance(contents, dict):
                    return contents.get("result", contents)
                for item in result.get("content", []):
                    if item.get("type") == "text":
                        data = json.loads(item["text"])
                        if isinstance(data, dict):
                            return data
                raise RuntimeError("Tool returned no object: " + name)
            try:
                made = tool("create_sandbox", {
                    "lifetime_seconds": 180, "idle_seconds": 60,
                    "cpu": 0.125, "memory_mib": 256,
                })
                sandbox_id = made["sandbox_id"]
                ran = tool("exec_command", {
                    "sandbox_id": sandbox_id,
                    "command": "printf 'LIVE_OAUTH_OK\\n'",
                    "timeout_seconds": 15,
                })
                assert ran["exit_code"] == 0 and "LIVE_OAUTH_OK" in ran["stdout"]
                print("Live OAuth tool calls: create_sandbox and exec_command OK")
            finally:
                if sandbox_id is not None:
                    try:
                        result = tool("terminate_sandbox", {"sandbox_id": sandbox_id})
                        assert result["terminated"] is True
                        print("Live OAuth sandbox terminated")
                    except Exception:
                        print("MCP termination failed; attempting SDK cleanup")
                        sb = modal.Sandbox.from_id(sandbox_id)
                        try:
                            sb.terminate()
                            print("SDK cleanup succeeded")
                        finally:
                            sb.detach()
    return {"cimd": "ok", "oauth": "ok", "tools": 6, "sandbox": "terminated"}


@app.local_entrypoint()
def main():
    result = verify_live_oauth.remote()
    print("PASS live self-hosted Modal MCP OAuth:", result)
