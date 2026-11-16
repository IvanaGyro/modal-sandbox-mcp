"""Live Exit Snapshot, cost-based idle policy, resume and deletion smoke.

Uses the deployed MCP with the existing Modal Secret; no tokens are logged.
Creates two tiny CPU-only Sandboxes, verifies retention and explicitly deletes their snapshots.
"""
from __future__ import annotations

import modal

app = modal.App("modal-sandbox-mcp-exit-snapshot-smoke")
image = modal.Image.debian_slim(python_version="3.12").pip_install("httpx>=0.27,<1")
ENDPOINT = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp"


@app.function(image=image, secrets=[modal.Secret.from_name("modal-mcp-auth")], timeout=600)
def verify():
    import json
    import os
    import httpx
    import modal

    bearer = os.environ.get("MCP_DEV_BEARER_TOKEN")
    if not bearer:
        raise RuntimeError("Legacy bearer required by this opt-in smoke test")
    headers = {
        "Authorization": "Bearer " + bearer,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }

    def decode(response):
        response.raise_for_status()
        if "text/event-stream" in response.headers.get("content-type", ""):
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    result = json.loads(line[5:].strip())
                    if "result" in result or "error" in result:
                        return result
            raise RuntimeError("SSE result missing")
        return response.json()

    identifiers = []
    with httpx.Client(headers=headers, timeout=180) as client:
        seq = 0

        def call(name, args):
            nonlocal seq
            seq += 1
            res = decode(client.post(ENDPOINT, json={
                "jsonrpc": "2.0", "id": seq, "method": "tools/call",
                "params": {"name": name, "arguments": args}
            }))
            if "error" in res:
                raise RuntimeError(f"{name}: {str(res['error'])[:500]}")
            payload = res["result"]
            if payload.get("isError"):
                raise RuntimeError(f"{name}: {str(payload['content'])[:1000]}")
            structured = payload.get("structuredContent")
            if isinstance(structured, dict):
                return structured.get("result", structured)
            for part in payload.get("content", []):
                if part.get("type") == "text":
                    return json.loads(part["text"])
            raise RuntimeError("Missing result in " + name)

        try:
            # Create test A and verify calculated budget, snapshot opt-in.
            first = call("create_sandbox", {
                "lifetime_seconds": 360,
                "cpu": 0.125,
                "memory_mib": 128,
            })
            first_id = first["sandbox_id"]
            identifiers.append(first_id)
            assert first["exit_snapshot_enabled"] is True, first
            policy = first["idle_policy"]
            assert policy["idle_budget_usd"] == 0.283824
            assert policy["calculated_idle_seconds"] > 360
            assert policy["idle_seconds"] == 360
            assert policy["idle_capped_by_lifetime"] is True
            print("Snapshot enabled; calculated and capped idle policy returned", flush=True)

            marker = "/tmp/exit-snapshot-marker.txt"
            call("write_file", {"sandbox_id": first_id, "path": marker,
                                "content": "persisted-from-exit-snapshot"})

            # Simulate an automatic timeout: terminate via Modal SDK, NOT
            # terminate_sandbox. Exit Snapshot remains available for resume.
            sb = modal.Sandbox.from_id(first_id)
            try:
                sb.terminate(wait=True)
            finally:
                sb.detach()
            print("Unmanaged exit snapshot created", flush=True)

            resumed = call("resume_sandbox", {"sandbox_id": first_id})
            resumed_id = resumed["sandbox_id"]
            identifiers.append(resumed_id)
            assert resumed_id != first_id
            assert resumed["restored_from_sandbox_id"] == first_id
            assert resumed["exit_snapshot_enabled"] is True
            assert resumed["processes_restored"] is False
            restored_text = call("read_path", {"sandbox_id": resumed_id, "path": marker})
            assert restored_text["content"] == "persisted-from-exit-snapshot"
            print("Exit Snapshot resume recovered filesystem contents", flush=True)

            stopped = call("terminate_sandbox", {"sandbox_id": resumed_id})
            assert stopped["terminated"] is True
            assert stopped["snapshot_deleted"] is False, stopped
            assert stopped["exit_snapshot"]["status"] == "ready", stopped
            listed = call("list_snapshots", {})
            assert any(row["sandbox_id"] == resumed_id and row["status"] == "ready"
                       for row in listed["snapshots"]), listed
            print("MCP termination retained a listed Exit Snapshot", flush=True)

            # Explicit deletion is a separate operation, and is idempotent.
            deleted = call("delete_snapshot", {"sandbox_id": resumed_id})
            assert deleted["deleted"] is True and deleted["status"] == "deleted", deleted
            # Regression: the old code resurrected the inventory entry when
            # terminate_sandbox was invoked again after explicit deletion.
            stopped_again = call("terminate_sandbox", {"sandbox_id": resumed_id})
            assert stopped_again["terminated"] is True, stopped_again
            assert stopped_again["snapshot_deleted"] is True, stopped_again
            assert stopped_again["exit_snapshot"]["status"] == "deleted", stopped_again
            after_delete = call("list_snapshots", {})
            assert all(item["sandbox_id"] != resumed_id
                       for item in after_delete["snapshots"]), after_delete
            again = call("delete_snapshot", {"sandbox_id": resumed_id})
            assert again["status"] == "already_deleted", again

            # Second explicit termination, without prior resume, also retains
            # the snapshot, which can be independently deleted.
            second = call("create_sandbox", {
                "lifetime_seconds": 360,
                "cpu": 0.125,
                "memory_mib": 128,
            })
            second_id = second["sandbox_id"]
            identifiers.append(second_id)
            result = call("terminate_sandbox", {"sandbox_id": second_id})
            assert result["terminated"] is True and not result["snapshot_deleted"], result
            assert result["exit_snapshot"]["status"] == "ready", result
            removed = call("delete_snapshot", {"sandbox_id": second_id})
            assert removed["deleted"] is True, removed
            # Clean up the original source snapshot left after resume.
            original_removed = call("delete_snapshot", {"sandbox_id": first_id})
            assert original_removed["deleted"] is True, original_removed
            print("Explicit snapshot deletion succeeded", flush=True)

            listed = call("list_snapshots", {})
            assert all(row["sandbox_id"] not in identifiers
                       for row in listed["snapshots"]), listed

            return {"pricing": "OK", "snapshot": "OK", "resume": "OK",
                    "retain_on_terminate": "OK", "explicit_delete": "OK"}
        finally:
            # Avoid orphan computation if RPC fails.
            for sandbox_id in identifiers:
                sb = modal.Sandbox.from_id(sandbox_id)
                try:
                    if sb.poll() is None:
                        sb.terminate(wait=True)
                        print("Emergency terminated a test Sandbox", flush=True)
                finally:
                    sb.detach()


@app.local_entrypoint()
def main():
    print("PASS live Exit Snapshot lifecycle:", verify.remote(), flush=True)
