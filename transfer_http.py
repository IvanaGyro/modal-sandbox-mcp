"""Bounded, signed HTTPS file transfers for Modal MCP.

MCP tools return only short-lived URLs. File bytes never enter MCP JSON-RPC
responses. Sandbox-to-server copies use Modal's streaming Filesystem API.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import tempfile
import time
from urllib.parse import quote

import modal

BASE_URL = "https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run"
TRANSFER_VOLUME = modal.Volume.from_name("modal-sandbox-mcp-transfer-cache", create_if_missing=True)
WORKSPACE_VOLUME = modal.Volume.from_name("modal-sandbox-mcp-workspace", create_if_missing=True)
EXPORT_DIR = Path("/transfer-staging/exports")
USED_DIR = Path("/transfer-staging/used")
MAX_TRANSFER_BYTES = 256 * 1024 * 1024
DEFAULT_EXPIRES_SECONDS = 600
MAX_EXPIRES_SECONDS = 3600
MAX_EXPORTS = 20
MAX_EXPORT_STORAGE = 1024 * 1024 * 1024
_TOKEN_VERSION = 1
_SAFE_ID = re.compile(r"^[a-f0-9]{32}$")


def _key() -> bytes:
    secret = (
        os.getenv("MCP_TRANSFER_SIGNING_KEY")
        or os.getenv("MCP_AUTH_PASSPHRASE")
        or os.getenv("MCP_DEV_BEARER_TOKEN")
    )
    if not secret or len(secret) < 32:
        raise RuntimeError("Configure a stable 32+ character transfer signing key")
    return hashlib.sha256(("modal-mcp-transfer-v1:" + secret).encode()).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def safe_path(path: str) -> str:
    """Require a fully qualified Sandbox path; reject traversal and NUL."""
    if (
        not isinstance(path, str)
        or len(path) > 1024
        or not path.startswith("/")
        or "\x00" in path
        or any(part == ".." for part in PurePosixPath(path).parts)
    ):
        raise ValueError("Expected an absolute Sandbox path without parent traversal")
    return path


def make_token(claims: dict) -> str:
    body = json.dumps(
        {"v": _TOKEN_VERSION, **claims},
        separators=(",", ":"), sort_keys=True
    ).encode()
    encoded = _b64(body)
    signature = hmac.new(_key(), encoded.encode("ascii"), hashlib.sha256).digest()
    return encoded + "." + _b64(signature)


def parse_token(token: str, operation: str) -> dict:
    from starlette.exceptions import HTTPException

    try:
        if len(token) > 3200:
            raise ValueError("token too long")
        body, signature = token.split(".", 1)
        expected = hmac.new(_key(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(signature), expected):
            raise ValueError("Invalid transfer token")
        data = json.loads(_unb64(body))
        if data.get("v") != _TOKEN_VERSION or data.get("op") != operation:
            raise ValueError("Incorrect transfer operation")
        if int(data.get("exp", 0)) < time.time():
            raise ValueError("Transfer link has expired")
        return data
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=403, detail="Invalid or expired transfer link") from exc


def _validate_expiry(seconds: int) -> int:
    if not isinstance(seconds, int) or not 60 <= seconds <= MAX_EXPIRES_SECONDS:
        raise ValueError("expires_in_seconds must be 60–3600")
    return int(time.time()) + seconds


def _validate_sha256(sha256: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{64}", sha256.lower()):
        raise ValueError("sha256 must be 64 hex characters")
    return sha256.lower()


def make_upload_link(
    sandbox_id: str, path: str, size_bytes: int, sha256: str,
    expires_in_seconds: int = DEFAULT_EXPIRES_SECONDS,
) -> dict:
    path = safe_path(path)
    if not 1 <= size_bytes <= MAX_TRANSFER_BYTES:
        raise ValueError("size_bytes must be 1–268435456 (256 MiB)")
    sha256 = _validate_sha256(sha256)
    expires = _validate_expiry(expires_in_seconds)
    token = make_token({
        "op": "upload", "sid": sandbox_id, "path": path,
        "bytes": size_bytes, "sha256": sha256, "exp": expires,
        "id": secrets.token_hex(16),
    })
    return {
        "upload_url": BASE_URL + "/transfer/upload/" + token,
        "method": "PUT",
        "content_type": "application/octet-stream",
        "size_bytes": size_bytes,
        "sha256": sha256,
        "expires_at_unix": expires,
        "instruction": "PUT raw file bytes; no MCP Base64 payload.",
    }


def _cleanup_exports() -> int:
    """Delete exports older than the maximum signed-URL lifetime."""
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    USED_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()
    deleted = 0
    for item in EXPORT_DIR.iterdir():
        if not item.is_file() or not item.name.endswith(".bin"):
            continue
        if now - item.stat().st_mtime > MAX_EXPIRES_SECONDS + 90:
            item.unlink(missing_ok=True)
            deleted += 1
    for item in USED_DIR.iterdir():
        if item.is_file() and _SAFE_ID.fullmatch(item.name):
            if now - item.stat().st_mtime > MAX_EXPIRES_SECONDS + 90:
                item.unlink(missing_ok=True)
                deleted += 1
    return deleted


def create_download_link(
    sandbox_id: str, path: str, expires_in_seconds: int = DEFAULT_EXPIRES_SECONDS
) -> dict:
    """Copy a Sandbox file to a persistent staging Volume and sign a GET URL."""
    path = safe_path(path)
    expires = _validate_expiry(expires_in_seconds)
    _cleanup_exports()
    exports = list(EXPORT_DIR.glob("*.bin"))
    if len(exports) >= MAX_EXPORTS or sum(p.stat().st_size for p in exports) >= MAX_EXPORT_STORAGE:
        raise RuntimeError("Transfer staging quota reached; revoke or wait for expiry")
    file_id = secrets.token_hex(16)
    stage = EXPORT_DIR / (file_id + ".bin")
    sb = modal.Sandbox.from_id(sandbox_id)
    try:
        info = sb.filesystem.stat(path)
        if int(info.size) > MAX_TRANSFER_BYTES:
            raise ValueError("Export exceeds 256 MiB; split or compress the file")
        sb.filesystem.copy_to_local(path, stage)
    finally:
        sb.detach()

    try:
        size = stage.stat().st_size
        if not 1 <= size <= MAX_TRANSFER_BYTES:
            raise ValueError("Export must be nonempty and at most 256 MiB")
        with open(stage, "rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        TRANSFER_VOLUME.commit()
        basename = PurePosixPath(path).name or "download.bin"
        token = make_token({
            "op": "download", "id": file_id, "exp": expires,
            "name": basename, "bytes": size, "sha256": digest,
        })
        return {
            "download_url": BASE_URL + "/transfer/download/" + token,
            "filename": basename,
            "size_bytes": size,
            "sha256": digest,
            "expires_at_unix": expires,
        }
    except Exception:
        stage.unlink(missing_ok=True)
        TRANSFER_VOLUME.commit()
        raise


def revoke_download_link(token: str) -> dict:
    payload = parse_token(token, "download")
    file_id = payload["id"]
    if not _SAFE_ID.fullmatch(file_id):
        raise ValueError("Invalid export ID")
    path = EXPORT_DIR / (file_id + ".bin")
    existed = path.exists()
    path.unlink(missing_ok=True)
    TRANSFER_VOLUME.commit()
    return {"revoked": existed}


def install_transfer_routes(mcp) -> None:
    """Register signed public HTTP routes on the authenticated MCP ASGI app."""
    from starlette.requests import Request
    from starlette.responses import FileResponse, JSONResponse
    from starlette.exceptions import HTTPException

    # Single ASGI container means this lock serializes uploads with the same
    # token and provides one-use upload URLs. Other uploads remain safe too.
    upload_lock = asyncio.Lock()

    @mcp.custom_route("/transfer/upload/{token}", methods=["PUT"])
    async def upload(request: Request):
        token = request.path_params["token"]
        data = parse_token(token, "upload")
        upload_id = data["id"]
        if not _SAFE_ID.fullmatch(upload_id):
            raise HTTPException(status_code=403)
        size = int(data["bytes"])
        if not 1 <= size <= MAX_TRANSFER_BYTES:
            raise HTTPException(status_code=403)
        expected_hash = data["sha256"]
        remote_path = safe_path(data["path"])

        async with upload_lock:
            USED_DIR.mkdir(parents=True, exist_ok=True)
            if (USED_DIR / upload_id).exists():
                return JSONResponse({"error": "upload already consumed"}, status_code=409)

            length = request.headers.get("content-length")
            if length and int(length) > size:
                return JSONResponse({"error": "upload exceeds expected length"}, status_code=413)

            checksum = hashlib.sha256()
            total = 0
            local = None
            try:
                with tempfile.NamedTemporaryFile(prefix="modal-mcp-upload-", delete=False) as tmp:
                    local = tmp.name
                    async for chunk in request.stream():
                        total += len(chunk)
                        if total > size:
                            raise HTTPException(status_code=413, detail="Upload too large")
                        checksum.update(chunk)
                        tmp.write(chunk)
                if total != size or not hmac.compare_digest(checksum.hexdigest(), expected_hash):
                    return JSONResponse(
                        {"error": "size or SHA-256 mismatch"}, status_code=422
                    )

                def copy_to_sandbox():
                    sb = modal.Sandbox.from_id(data["sid"])
                    try:
                        sb.filesystem.copy_from_local(local, remote_path)
                    finally:
                        sb.detach()

                await asyncio.to_thread(copy_to_sandbox)
                (USED_DIR / upload_id).write_text(str(time.time()))
                await TRANSFER_VOLUME.commit.aio()
                return JSONResponse(
                    {"ok": True, "path": remote_path, "size_bytes": size,
                     "sha256": checksum.hexdigest()},
                    headers={"Cache-Control": "no-store"}
                )
            finally:
                if local:
                    Path(local).unlink(missing_ok=True)

    @mcp.custom_route("/transfer/download/{token}", methods=["GET"])
    async def download(request: Request):
        claims = parse_token(request.path_params["token"], "download")
        file_id = claims["id"]
        if not _SAFE_ID.fullmatch(file_id):
            raise HTTPException(status_code=403)
        path = EXPORT_DIR / (file_id + ".bin")
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Export has expired or was revoked")
        if path.stat().st_size != claims["bytes"]:
            raise HTTPException(status_code=409, detail="Export changed")
        filename = str(claims["name"]).replace("/", "_").replace("\\", "_")
        return FileResponse(
            path=path,
            media_type="application/octet-stream",
            filename=filename,
            headers={
                "Cache-Control": "private, no-store, max-age=0",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )
