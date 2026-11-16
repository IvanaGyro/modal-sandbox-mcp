"""Persistent inventory for MCP-managed Sandbox Exit Snapshots.

Exit Snapshots belong to Modal, not to the inventory. The local records let
list_snapshots discover stopped Sandboxes after a web-container restart.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid

INDEX_DIR = Path("/snapshot-index/records")
_VALID_ID = re.compile(r"^sb-[A-Za-z0-9_-]{3,150}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_path(sandbox_id: str, directory: Path) -> Path:
    if not isinstance(sandbox_id, str) or not _VALID_ID.fullmatch(sandbox_id):
        raise ValueError("Invalid Sandbox ID")
    return directory / (sandbox_id + ".json")


def read_record(sandbox_id: str, *, directory: Path = INDEX_DIR) -> dict | None:
    path = _record_path(sandbox_id, directory)
    if not path.is_file():
        return None
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("sandbox_id") != sandbox_id:
        raise ValueError("Corrupted snapshot index entry")
    return record


def write_record(sandbox_id: str, *, directory: Path = INDEX_DIR, **changes) -> dict:
    path = _record_path(sandbox_id, directory)
    directory.mkdir(parents=True, exist_ok=True)
    record = read_record(sandbox_id, directory=directory) or {
        "sandbox_id": sandbox_id,
        "registered_at": utc_now(),
    }
    record.update(changes)
    record["updated_at"] = utc_now()
    # Write a complete JSON record before replacing the old version.
    temporary = directory / (path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return record


def list_records(*, directory: Path = INDEX_DIR) -> list[dict]:
    if not directory.exists():
        return []
    records = []
    for path in directory.glob("sb-*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("sandbox_id") != path.stem:
            raise ValueError("Corrupted snapshot index entry")
        records.append(record)
    return sorted(records, key=lambda record: record["registered_at"], reverse=True)


def inspect_exit_snapshot(sandbox, *, timeout_seconds: int = 0) -> dict:
    """Check the Exit Snapshot without creating another Sandbox/Image."""
    if sandbox.poll() is None:
        return {"status": "running", "image_id": None}
    try:
        snapshot = sandbox._experimental_get_exit_snapshot(timeout=timeout_seconds)
        image_id = snapshot.object_id
        if not isinstance(image_id, str) or not image_id.startswith("im-"):
            return {"status": "unavailable", "image_id": None,
                    "reason": "Modal returned an invalid snapshot Image ID"}
        return {"status": "ready", "image_id": image_id}
    except Exception as exc:
        return {
            "status": "pending" if type(exc).__name__ == "TimeoutError" else "unavailable",
            "image_id": None,
            "error_type": type(exc).__name__,
        }
