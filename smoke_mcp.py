"""End-to-end authenticated MCP initialize and tools/list smoke test.

Runs in Modal with the existing modal-mcp-auth Secret. No credential is logged.
This tests the deployed HTTPS service, not a local in-process FastMCP server.
"""

from __future__ import annotations

import modal

app = modal.App("modal-sandbox-mcp-protocol-smoke")
image = modal.Image.debian_slim(python_version="3.12").pip_install("httpx>=0.27,<1")
ENDPOINT = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp"
EXPECTED_TOOLS = {
    "create_sandbox",
    "exec_command",
    "read_file",
    "write_file",
    "sandbox_status",
    "terminate_sandbox",
}


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("modal-mcp-auth")],
    timeout=120,
)
def verify_tools_list() -> dict:
    import json
    import os

    import httpx

    auth_mode = os.getenv("MCP_AUTH_MODE")
    if auth_mode != "static-dev":
        raise RuntimeError(
            "Smoke test currently requires static-dev mode; never print secrets. "
            f"Configured auth mode: {auth_mode!r}"
        )
    token = os.environ["MCP_DEV_BEARER_TOKEN"]
    if len(token) < 32:
        raise RuntimeError("MCP bearer token is too short")

    def decode(response: httpx.Response) -> dict:
        response.raise_for_status()
        kind = response.headers.get("content-type", "").lower()
        if "text/event-stream" in kind:
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    item = json.loads(line[5:].strip())
                    if "result" in item or "error" in item:
                        return item
            raise RuntimeError("SSE response did not contain a JSON-RPC result")
        return response.json()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    with httpx.Client(headers=headers, timeout=60) as client:
        init = client.post(
            ENDPOINT,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "modal-mcp-smoke", "version": "1.0.0"},
                },
            },
        )
        initialized = decode(init)
        if "result" not in initialized:
            raise RuntimeError("MCP initialize failed: " + repr(initialized))
        protocol = initialized["result"].get("protocolVersion")
        if not protocol:
            raise RuntimeError("MCP initialize response lacks protocolVersion")

        # The server uses stateless HTTP, so session-affinity is not needed.
        # Announce initialization before asking for tools.
        notice = client.post(
            ENDPOINT, json={"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        if notice.status_code >= 400:
            raise RuntimeError(
                f"MCP initialized notification failed: HTTP {notice.status_code}"
            )

        result = decode(
            client.post(
                ENDPOINT,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
        )
        if "result" not in result:
            raise RuntimeError("MCP tools/list failed: " + repr(result))
        tools = result["result"].get("tools", [])
        names = {tool["name"] for tool in tools}
        if names != EXPECTED_TOOLS:
            raise RuntimeError(
                f"Tool catalog mismatch: found {sorted(names)}, "
                f"expected {sorted(EXPECTED_TOOLS)}"
            )
        return {"protocol_version": protocol, "tool_names": sorted(names)}


@app.local_entrypoint()
def main():
    result = verify_tools_list.remote()
    print(f"Authenticated MCP handshake OK: {result['protocol_version']}")
    print("MCP tools/list OK:")
    for name in result["tool_names"]:
        print(f"- {name}")
