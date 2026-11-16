"""End-to-end 100 MiB upload and download via real Modal MCP signed URLs.

The transfer bodies bypass MCP JSON-RPC. This test checks exact size and
SHA-256 both ways, exercises the directory tools and a persistent Volume,
and always terminates Sandboxes. Test data is randomly generated in Modal.
"""

from __future__ import annotations
import modal

app = modal.App("modal-sandbox-transfer-100mib-test")
image = modal.Image.debian_slim(python_version="3.12").pip_install("httpx>=0.27,<1")
URL = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp"
SIZE = 100 * 1024 * 1024


@app.function(image=image, secrets=[modal.Secret.from_name("modal-mcp-auth")], timeout=900)
def main_test():
    import hashlib
    import json
    import os
    from pathlib import Path
    import tempfile
    import time
    import httpx
    import modal

    token = os.environ["MCP_DEV_BEARER_TOKEN"]
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    sandbox_id = None
    with httpx.Client(headers=headers, timeout=240) as mcp, tempfile.TemporaryDirectory() as directory:
        seq = 0

        def decode(response):
            response.raise_for_status()
            if "text/event-stream" in response.headers.get("content-type", ""):
                for line in response.text.splitlines():
                    if line.startswith("data:"):
                        x = json.loads(line[5:].strip())
                        if "result" in x or "error" in x:
                            return x
                raise ValueError("SSE result missing")
            return response.json()

        def invoke(name, args):
            nonlocal seq
            seq += 1
            body = decode(mcp.post(URL, json={
                "jsonrpc": "2.0", "id": seq, "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }))
            if "error" in body:
                raise RuntimeError(name + ": " + str(body["error"])[:900])
            result = body["result"]
            if result.get("isError"):
                raise RuntimeError(name + ": " + str(result.get("content"))[:1200])
            d = result.get("structuredContent")
            if isinstance(d, dict):
                return d.get("result", d)
            for c in result.get("content", []):
                if c.get("type") == "text":
                    return json.loads(c["text"])
            raise ValueError("Missing tool result: " + name)

        local = Path(directory) / "upload.bin"
        digest = hashlib.sha256()
        with local.open("wb") as output:
            for _ in range(100):
                block = os.urandom(1024 * 1024)
                digest.update(block)
                output.write(block)
        expected = digest.hexdigest()
        assert local.stat().st_size == SIZE
        print("Generated random file: 104857600 bytes", flush=True)

        try:
            created = invoke("create_sandbox", {
                "lifetime_seconds": 900, "idle_seconds": 600,
                "cpu": 1.0, "memory_mib": 1024,
                "persistent_workspace": True,
            })
            sandbox_id = created["sandbox_id"]
            assert created["persistent_workspace"] is True
            print("Persistent-volume Sandbox created", flush=True)

            src = "/tmp/transfer-check.bin"
            signed = invoke("create_upload_link", {
                "sandbox_id": sandbox_id, "path": src,
                "size_bytes": SIZE, "sha256": expected,
                "expires_in_seconds": 1800,
            })
            assert signed["method"] == "PUT"
            assert signed["sha256"] == expected
            print("Signed upload link created (URL withheld)", flush=True)

            # Exclude MCP Authorization token when using a signed URL.
            upload_start = time.monotonic()
            with local.open("rb") as source:
                with httpx.Client(timeout=480) as http:
                    uploaded = http.put(
                        signed["upload_url"],
                        content=iter(lambda: source.read(1024 * 1024), b""),
                        headers={"Content-Type": "application/octet-stream"},
                    )
            assert uploaded.status_code == 200, (
                "HTTP upload status " + str(uploaded.status_code) + ": " + uploaded.text[:600]
            )
            assert uploaded.json()["sha256"] == expected
            print("100 MiB HTTP PUT succeeded in %.2fs" % (time.monotonic() - upload_start), flush=True)

            info = invoke("stat_path", {"sandbox_id": sandbox_id, "path": src})
            assert info["size_bytes"] == SIZE, info
            print("Remote file stat matches 100 MiB", flush=True)

            download = invoke("read_path", {
                "sandbox_id": sandbox_id, "path": src,
                "expires_in_seconds": 1800,
            })
            assert download["kind"] == "file" and download["delivery"] == "download"
            assert download["size_bytes"] == SIZE
            assert download["sha256"] == expected
            print("Signed download link created (URL withheld)", flush=True)

            dest = Path(directory) / "download.bin"
            fetched = hashlib.sha256()
            bytes_read = 0
            get_start = time.monotonic()
            with httpx.Client(timeout=480) as http:
                with http.stream("GET", download["download_url"]) as response:
                    assert response.status_code == 200, "HTTP download " + str(response.status_code)
                    with dest.open("wb") as target:
                        for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                            target.write(chunk)
                            fetched.update(chunk)
                            bytes_read += len(chunk)
            assert bytes_read == SIZE, (bytes_read, SIZE)
            assert fetched.hexdigest() == expected
            print("100 MiB HTTP GET succeeded in %.2fs; SHA-256 exact match" %
                  (time.monotonic() - get_start), flush=True)

            revoked = invoke("revoke_download_link", {
                "download_url": download["download_url"]
            })
            assert revoked["revoked"] is True
            print("Staged 100 MiB export revoked and deleted", flush=True)

            text_path = "/workspace/small-test.txt"
            invoke("write_file", {
                "sandbox_id": sandbox_id, "path": text_path,
                "content": "繁體中文🌈abcd",
            })
            part = invoke("read_path", {
                "sandbox_id": sandbox_id, "path": text_path,
            })
            assert part["content"] == "繁體中文🌈abcd", part
            assert part["delivery"] == "inline"
            folder = "/workspace/mcp-transfer-test-dir"
            invoke("make_directory", {"sandbox_id": sandbox_id, "path": folder})
            invoke("write_file", {"sandbox_id": sandbox_id, "path": folder + "/a.txt",
                                  "content": "archive test A"})
            invoke("write_file", {"sandbox_id": sandbox_id, "path": folder + "/b.txt",
                                  "content": "archive test B"})
            zipped = invoke("read_path", {
                "sandbox_id": sandbox_id, "path": folder, "expires_in_seconds": 1800,
            })
            assert zipped["kind"] == "directory" and zipped["delivery"] == "download"
            assert zipped["filename"].endswith(".zip"), zipped
            import zipfile
            from io import BytesIO
            with httpx.Client(timeout=120) as http:
                zip_result = http.get(zipped["download_url"])
            assert zip_result.status_code == 200, zip_result.status_code
            with zipfile.ZipFile(BytesIO(zip_result.content)) as archive:
                names = archive.namelist()
                assert any(x.endswith("/a.txt") for x in names), names
                assert any(x.endswith("/b.txt") for x in names), names
            invoke("revoke_download_link", {"download_url": zipped["download_url"]})
            print("Directory ZIP export and revocation: OK", flush=True)

            invoke("commit_workspace", {"sandbox_id": sandbox_id})
            listed = invoke("list_directory", {
                "sandbox_id": sandbox_id, "path": "/workspace"
            })
            assert any(e["name"] == "small-test.txt" for e in listed["entries"])
            print("Automatic UTF-8 inline read, directory listing, persistent-volume commit: OK",
                  flush=True)

            # Verify that the committed state is visible in a different Sandbox.
            secondary_id = None
            try:
                secondary = invoke("create_sandbox", {
                    "lifetime_seconds": 300, "idle_seconds": 180,
                    "cpu": 0.125, "memory_mib": 256,
                    "persistent_workspace": True,
                })
                secondary_id = secondary["sandbox_id"]
                persisted = invoke("read_path", {
                    "sandbox_id": secondary_id, "path": text_path,
                })
                assert persisted["content"] == "繁體中文🌈abcd"
                print("Persistent Volume recovered in a second Sandbox: OK", flush=True)
                invoke("remove_path", {"sandbox_id": secondary_id, "path": text_path})
                invoke("remove_path", {
                    "sandbox_id": secondary_id, "path": folder, "recursive": True,
                })
                invoke("commit_workspace", {"sandbox_id": secondary_id})
            finally:
                if secondary_id:
                    invoke("terminate_sandbox", {"sandbox_id": secondary_id})
            invoke("remove_path", {"sandbox_id": sandbox_id, "path": src})
            print("Remote 100 MiB test file deleted", flush=True)
        finally:
            if sandbox_id:
                try:
                    invoke("terminate_sandbox", {"sandbox_id": sandbox_id})
                    print("Test Sandbox terminated", flush=True)
                except Exception:
                    sb = modal.Sandbox.from_id(sandbox_id)
                    try:
                        sb.terminate()
                    finally:
                        sb.detach()
    return {"size_bytes": SIZE, "sha256": expected, "upload": "OK",
            "download": "OK", "sandbox": "terminated"}


@app.local_entrypoint()
def main():
    report = main_test.remote()
    print("PASS 100 MiB HTTPS round-trip:", report, flush=True)
