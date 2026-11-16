"""One-shot end-to-end MCP sandbox smoke test, running in Modal.

Exercises authenticated tools/call over HTTPS. A created Sandbox is always
terminated in a finally block. Do not pass secrets to the sandbox.
"""
from __future__ import annotations

import modal

ENDPOINT = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp"
app = modal.App("modal-sandbox-mcp-e2e")
image = modal.Image.debian_slim(python_version="3.12").pip_install("httpx>=0.27,<1")


@app.function(image=image, secrets=[modal.Secret.from_name("modal-mcp-auth")], timeout=240)
def run_e2e() -> dict:
    import json
    import os
    import httpx

    if os.getenv("MCP_AUTH_MODE") != "static-dev":
        raise RuntimeError("E2E requires current static-dev credentials; secrets are never printed")

    bearer = os.environ["MCP_DEV_BEARER_TOKEN"]
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    sandbox_id = None

    def parse(response: httpx.Response) -> dict:
        response.raise_for_status()
        if "text/event-stream" in response.headers.get("content-type", ""):
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    value = json.loads(line[5:].strip())
                    if "result" in value or "error" in value:
                        return value
            raise RuntimeError("No JSON-RPC result in SSE stream")
        return response.json()

    with httpx.Client(headers=headers, timeout=90) as client:
        counter = 1

        def invoke(name: str, arguments: dict) -> dict:
            nonlocal counter
            counter += 1
            response = parse(client.post(ENDPOINT, json={
                "jsonrpc": "2.0", "id": counter, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }))
            if "error" in response:
                raise RuntimeError(f"{name}: JSON-RPC error: {response['error']}")
            result = response["result"]
            if result.get("isError"):
                raise RuntimeError(f"{name}: Tool error: {result.get('content', [])}")
            data = result.get("structuredContent")
            if isinstance(data, dict):
                if "result" in data and isinstance(data["result"], dict):
                    return data["result"]
                return data
            content = result.get("content", [])
            for c in content:
                if c.get("type") == "text":
                    parsed = json.loads(c["text"])
                    if isinstance(parsed, dict):
                        return parsed
            raise RuntimeError(f"{name}: no dict tool result")

        try:
            created = invoke("create_sandbox", {
                "lifetime_seconds": 300, "idle_seconds": 90,
                "cpu": 0.125, "memory_mib": 256,
            })
            sandbox_id = created["sandbox_id"]
            print("create_sandbox: OK (5-minute hard lifetime, 90s idle)")
            executed = invoke("exec_command", {
                "sandbox_id": sandbox_id, "command": "printf 'MCP_SHELL_OK\\n'",
                "timeout_seconds": 15,
            })
            assert executed["exit_code"] == 0, executed
            assert "MCP_SHELL_OK" in executed["stdout"], executed
            print("exec_command: OK (exit_code=0, expected stdout)")
            wrote = invoke("write_file", {
                "sandbox_id": sandbox_id,
                "path": "/tmp/mcp-e2e/note.txt",
                "content": "modal-mcp-file-roundtrip",
            })
            assert wrote["bytes_written"] == len("modal-mcp-file-roundtrip")
            print("write_file: OK")
            read = invoke("read_path", {
                "sandbox_id": sandbox_id, "path": "/tmp/mcp-e2e/note.txt",
            })
            assert read["content"] == "modal-mcp-file-roundtrip", read
            print("read_path: OK (contents match)")
            status = invoke("sandbox_status", {"sandbox_id": sandbox_id})
            assert status["running"] is True, status
            print("sandbox_status: OK (running)")
            return {"exec": "passed", "files": "passed", "status": "passed"}
        finally:
            if sandbox_id:
                try:
                    result = invoke("terminate_sandbox", {"sandbox_id": sandbox_id})
                    assert result.get("terminated") is True
                    print("terminate_sandbox: OK")
                except Exception as exc:
                    # Cleanup must remain effective if MCP invocation failed.
                    print(f"Remote terminate failed; using Modal SDK fallback: {type(exc).__name__}")
                    sb = modal.Sandbox.from_id(sandbox_id)
                    try:
                        sb.terminate(wait=True)
                        print("Modal SDK forced termination: OK")
                    finally:
                        sb.detach()


@app.local_entrypoint()
def main():
    report = run_e2e.remote()
    print("End-to-end smoke test passed:", report)
