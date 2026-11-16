"""Live integration test of automatic read_path dispatch (no offsets).

Runs against the production MCP URL using a Modal Secret in a separate
function. Tests small Unicode text, larger text, small binary bytes and a
directory ZIP. All signed URLs stay out of test logs. Sandbox and exports are
always cleaned up.
"""

from __future__ import annotations

import modal

APP = modal.App("modal-sandbox-read-path-smoke")
IMAGE = modal.Image.debian_slim(python_version="3.12").pip_install("httpx>=0.27,<1")
MCP_URL = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp"


@APP.function(
    image=IMAGE,
    secrets=[modal.Secret.from_name("modal-mcp-auth")],
    timeout=360,
)
def verify_read_path():
    import hashlib
    from io import BytesIO
    import json
    import os
    import zipfile

    import httpx

    token = os.environ.get("MCP_DEV_BEARER_TOKEN")
    if not token:
        raise RuntimeError("Current regression test requires legacy bearer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    sandbox_id = None

    def decode(resp):
        resp.raise_for_status()
        if "text/event-stream" in resp.headers.get("content-type", ""):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    parsed = json.loads(line[5:].strip())
                    if "result" in parsed or "error" in parsed:
                        return parsed
            raise RuntimeError("No result in SSE response")
        return resp.json()

    with httpx.Client(headers=headers, timeout=180) as client:
        seq = 0

        def call(name, args):
            nonlocal seq
            seq += 1
            result = decode(client.post(MCP_URL, json={
                "jsonrpc": "2.0", "id": seq, "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }))
            if "error" in result:
                raise RuntimeError(name + ": " + str(result["error"])[:500])
            payload = result["result"]
            if payload.get("isError"):
                raise RuntimeError(name + ": " + str(payload["content"])[:500])
            structured = payload.get("structuredContent")
            if isinstance(structured, dict):
                return structured.get("result", structured)
            for part in payload.get("content", []):
                if part.get("type") == "text":
                    return json.loads(part["text"])
            raise RuntimeError("No structured response from " + name)

        listed = decode(client.post(MCP_URL, json={
            "jsonrpc": "2.0", "id": 999,
            "method": "tools/list", "params": {},
        }))["result"]["tools"]
        names = {t["name"] for t in listed}
        assert "read_path" in names, names
        assert not ({"read_file", "create_download_link",
                     "create_directory_download_link"} & names), names
        props = next(t for t in listed if t["name"] == "read_path")["inputSchema"]["properties"]
        assert "offset" not in props and "max_bytes" not in props
        print("Catalog: unified read_path, no offset, old read tools removed", flush=True)

        try:
            created = call("create_sandbox", {
                "lifetime_seconds": 300, "idle_seconds": 240,
                "cpu": 0.125, "memory_mib": 256,
            })
            sandbox_id = created["sandbox_id"]

            small = "/tmp/mcp-read-small.txt"
            content = "繁體中文：小檔案🌈\n"
            call("write_file", {
                "sandbox_id": sandbox_id, "path": small, "content": content
            })
            inline = call("read_path", {"sandbox_id": sandbox_id, "path": small})
            assert inline["kind"] == "file" and inline["delivery"] == "inline", inline
            assert inline["content"] == content
            assert "download_url" not in inline
            print("Small UTF-8 text: inline without offset", flush=True)

            def check_download(path, expected, kind="file"):
                result = call("read_path", {"sandbox_id": sandbox_id, "path": path})
                assert result["kind"] == kind and result["delivery"] == "download", result
                with httpx.Client(timeout=90) as http:
                    response = http.get(result["download_url"])
                assert response.status_code == 200, response.status_code
                assert hashlib.sha256(response.content).hexdigest() == result["sha256"]
                if kind == "file":
                    assert response.content == expected
                call("revoke_download_link", {"download_url": result["download_url"]})
                return response.content

            big = "/tmp/mcp-read-large.txt"
            large_data = "ABC語言".encode("utf-8") * 1700  # > 8 KiB
            call("write_file", {
                "sandbox_id": sandbox_id, "path": big,
                "content": large_data.decode("utf-8"),
            })
            check_download(big, large_data)
            print("Large UTF-8: signed HTTPS download", flush=True)

            binary = "/tmp/mcp-read-binary.bin"
            call("exec_command", {
                "sandbox_id": sandbox_id,
                "command": "python -c \"open('/tmp/mcp-read-binary.bin','wb').write(bytes([255,0,1,2]))\"",
            })
            check_download(binary, bytes([255, 0, 1, 2]))
            print("Small non-UTF-8 binary: signed HTTPS download", flush=True)

            folder = "/tmp/mcp-read-dir"
            call("make_directory", {"sandbox_id": sandbox_id, "path": folder})
            call("write_file", {
                "sandbox_id": sandbox_id, "path": folder + "/hello.txt",
                "content": "ZIP 中文內容",
            })
            zip_data = check_download(folder, None, kind="directory")
            with zipfile.ZipFile(BytesIO(zip_data)) as archive:
                filenames = archive.namelist()
                assert any(n.endswith("hello.txt") for n in filenames), filenames
                entry = next(n for n in filenames if n.endswith("hello.txt"))
                assert archive.read(entry).decode("utf-8") == "ZIP 中文內容"
            print("Directory: automatic ZIP download", flush=True)

            return {"small_text": "inline", "large_text": "link",
                    "binary": "link", "directory": "ZIP", "offset": "absent"}
        finally:
            if sandbox_id:
                try:
                    call("terminate_sandbox", {"sandbox_id": sandbox_id})
                    print("Sandbox terminated", flush=True)
                except Exception:
                    sandbox = modal.Sandbox.from_id(sandbox_id)
                    try:
                        sandbox.terminate()
                    finally:
                        sandbox.detach()


@APP.local_entrypoint()
def main():
    print("PASS live read_path:", verify_read_path.remote())
