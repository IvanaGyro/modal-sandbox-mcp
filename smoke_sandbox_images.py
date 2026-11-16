"""Live MCP test for selectable Sandbox Images.

Creates two CPU-only Sandboxes from public registries and always terminates.
No user credentials or large data are sent through MCP.
"""

from __future__ import annotations
import modal

app = modal.App("modal-sandbox-mcp-selectable-images-smoke")
image = modal.Image.debian_slim(python_version="3.12").pip_install("httpx>=0.27,<1")
ENDPOINT = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp"


@app.function(image=image, secrets=[modal.Secret.from_name("modal-mcp-auth")], timeout=900)
def verify():
    import json
    import os
    import httpx

    token = os.environ["MCP_DEV_BEARER_TOKEN"]
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    with httpx.Client(headers=headers, timeout=240) as client:
        serial = 0

        def rpc(method, arguments):
            nonlocal serial
            serial += 1
            response = client.post(ENDPOINT, json={
                "jsonrpc": "2.0", "id": serial, "method": "tools/call",
                "params": {"name": method, "arguments": arguments},
            })
            response.raise_for_status()
            result = None
            if "text/event-stream" in response.headers.get("content-type", ""):
                for line in response.text.splitlines():
                    if line.startswith("data:"):
                        obj = json.loads(line[5:].strip())
                        if "result" in obj or "error" in obj:
                            result = obj
                            break
            else:
                result = response.json()
            if not result or "error" in result or result["result"].get("isError"):
                raise RuntimeError(f"{method}: {str(result)[:1000]}")
            data = result["result"].get("structuredContent")
            if isinstance(data, dict):
                return data.get("result", data)
            for item in result["result"].get("content", []):
                if item.get("type") == "text":
                    return json.loads(item["text"])
            raise RuntimeError(f"{method}: missing response")

        test_cases = [
            {"name": "python-registry",
             "kwargs": {"image_ref": "python:3.12-slim-bookworm"},
             "command": "python --version && cat /etc/os-release | head -n 1"},
            {"name": "ubuntu-with-python-injection",
             "kwargs": {"image_ref": "ubuntu:22.04", "image_add_python": "3.12"},
             "command": "python --version && cat /etc/os-release | head -n 1"},
        ]
        for case in test_cases:
            sandbox_id = None
            try:
                created = rpc("create_sandbox", {
                    "lifetime_seconds": 420,
                    "cpu": 0.125, "memory_mib": 256,
                    **case["kwargs"],
                })
                sandbox_id = created["sandbox_id"]
                assert created["image_ref"] == case["kwargs"]["image_ref"], created
                assert created["image_source"] == "registry"
                print(case["name"] + ": Sandbox created", flush=True)

                executed = rpc("exec_command", {
                    "sandbox_id": sandbox_id,
                    "command": case["command"],
                    "timeout_seconds": 30,
                })
                assert executed["exit_code"] == 0, executed
                assert "Python 3.12" in executed["stdout"], executed
                print(case["name"] + ": shell OK", flush=True)

                path = "/tmp/mcp-image-probe.txt"
                rpc("write_file", {
                    "sandbox_id": sandbox_id, "path": path, "content": "custom-image-probe",
                })
                read = rpc("read_path", {
                    "sandbox_id": sandbox_id, "path": path,
                })
                assert read["content"] == "custom-image-probe", read
                print(case["name"] + ": filesystem OK", flush=True)
            finally:
                if sandbox_id:
                    try:
                        rpc("terminate_sandbox", {"sandbox_id": sandbox_id})
                        print(case["name"] + ": terminated", flush=True)
                    except Exception:
                        sb = modal.Sandbox.from_id(sandbox_id)
                        try:
                            sb.terminate()
                        finally:
                            sb.detach()
        return {"registry_image": "OK", "python_injection": "OK", "cleanup": "OK"}


@app.local_entrypoint()
def main():
    result = verify.remote()
    print("PASS configurable Sandbox Image selection:", result, flush=True)
