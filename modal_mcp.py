"""An authenticated, serverless MCP control plane for Modal Sandboxes.

Deployment: modal deploy modal_mcp.py
"""

from __future__ import annotations

import os

import modal
import modal.experimental
from typing import Literal
from sandbox_images import resolve_sandbox_image
from sandbox_lifecycle import (
    DEFAULT_LIFETIME_SECONDS, idle_budget_for, managed_tags,
    restored_settings, delete_exit_snapshot_of,
)
from path_reader import inspect_path
from oauth_support import AUTH_VOLUME, github_oauth, require_authorized_owner
from transfer_http import (
    TRANSFER_VOLUME, WORKSPACE_VOLUME, install_transfer_routes,
    make_upload_link, create_download_link as stage_download,
    revoke_download_link as revoke_staged_download,
    safe_path, _cleanup_exports,
)

APP_NAME = "modal-sandbox-mcp"
app = modal.App(APP_NAME)

# The web app and the sandbox use separate images. A web request never executes
# arbitrary user commands in the control-plane container.
web_image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "fastmcp>=3.4,<3.5", "pydantic>=2,<3"
).add_local_python_source("oauth_support").add_local_python_source("passphrase_oauth").add_local_python_source("transfer_http").add_local_python_source("sandbox_images").add_local_python_source("path_reader").add_local_python_source("sandbox_lifecycle")
sandbox_image = modal.Image.debian_slim(python_version="3.12").apt_install(
    "bash", "git", "curl", "ca-certificates", "build-essential"
)

MAX_COMMAND_SECONDS = 45
MAX_OUTPUT_CHARS = 24_000
MAX_FILE_CHARS = 100_000


def _auth_from_environment():
    """Fail closed: never deploy a publicly accessible unauthenticated shell."""
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier
    from pydantic import AnyHttpUrl

    mode = os.getenv("MCP_AUTH_MODE", "").strip().lower()
    if mode == "passphrase":
        from passphrase_oauth import PassphraseOAuthProvider

        return PassphraseOAuthProvider(
            passphrase=os.environ.get("MCP_AUTH_PASSPHRASE", "")
        )
    if mode == "github":
        return github_oauth()
    if mode == "oauth":
        keys = ["MCP_JWKS_URI", "MCP_ISSUER", "MCP_AUDIENCE", "MCP_AUTHORIZATION_SERVER", "MCP_BASE_URL"]
        missing = [key for key in keys if not os.getenv(key)]
        if missing:
            raise RuntimeError("Missing OAuth settings: " + ", ".join(missing))
        verifier = JWTVerifier(
            jwks_uri=os.environ["MCP_JWKS_URI"],
            issuer=os.environ["MCP_ISSUER"],
            audience=os.environ["MCP_AUDIENCE"],
        )
        return RemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[AnyHttpUrl(os.environ["MCP_AUTHORIZATION_SERVER"])],
            base_url=os.environ["MCP_BASE_URL"],
        )
    if mode == "static-dev":
        # Migration bootstrap: serve self-hosted OAuth with the previously
        # configured high-entropy bearer as the consent passphrase, while
        # still accepting that exact bearer for old test clients.
        # Prefer a separate MCP_AUTH_PASSPHRASE and mode=passphrase later.
        from passphrase_oauth import PassphraseOAuthProvider

        token = os.getenv("MCP_DEV_BEARER_TOKEN", "")
        if len(token) < 32:
            raise RuntimeError("MCP_DEV_BEARER_TOKEN must be at least 32 characters")
        return PassphraseOAuthProvider(passphrase=token, legacy_bearer=token)
    raise RuntimeError("MCP_AUTH_MODE must be passphrase, github, oauth, or static-dev; unauthenticated mode is forbidden")


def _clip(value: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    return value[:max_chars] + ("\n[output truncated]" if len(value) > max_chars else "")


def _get_sandbox(sandbox_id: str):
    if not sandbox_id or len(sandbox_id) > 160:
        raise ValueError("Invalid sandbox ID")
    return modal.Sandbox.from_id(sandbox_id)


@app.function(
    image=modal.Image.debian_slim(python_version="3.12"),
    volumes={"/transfer-staging": TRANSFER_VOLUME},
    schedule=modal.Period(hours=1),
)
def cleanup_transfer_cache():
    """Remove expired export files and consumed upload-token markers."""
    removed = _cleanup_exports()
    if removed:
        TRANSFER_VOLUME.commit()
    return {"removed": removed}


@app.function(
    image=web_image,
    secrets=[modal.Secret.from_name("modal-mcp-auth")],
    timeout=180,
    max_containers=1,
    volumes={"/oauth-state": AUTH_VOLUME, "/transfer-staging": TRANSFER_VOLUME},
)
@modal.concurrent(max_inputs=8)
@modal.asgi_app()
def mcp_web():
    """FastMCP handles MCP protocol, OAuth metadata and HTTP sessions."""
    from fastmcp import FastMCP

    auth_provider = _auth_from_environment()
    mcp = FastMCP("Modal Sandbox MCP", auth=auth_provider)
    install_transfer_routes(mcp)

    if os.getenv("MCP_AUTH_MODE", "").strip().lower() in ("passphrase", "static-dev"):
        from starlette.requests import Request

        @mcp.custom_route("/consent", methods=["GET", "POST"])
        async def oauth_consent(request: Request):
            return await auth_provider.consent(request)


    @mcp.tool
    def create_sandbox(
        lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
        cpu: float = 1.0,
        memory_mib: int = 1024,
        persistent_workspace: bool = False,
        image_ref: str | None = None,
        image_source: Literal["registry", "modal_name", "modal_id"] = "registry",
        image_add_python: str | None = None,
    ) -> dict:
        """Create a Linux Sandbox with a chosen Image.

        Default: prebuilt Debian/Python plus common developer tools.
        image_source="registry": pull a public OCI image (e.g.
        "python:3.12-slim-bookworm" or "ubuntu:22.04"); use
        image_add_python="3.12" if the image has no Python.
        image_source="modal_name": an Image published in your Modal workspace.
        image_source="modal_id": an existing Modal Image ID (im-...).
        Custom images need a POSIX /bin/sh and 'sleep' for their keepalive;
        read_file also requires 'python'. Image selection does NOT allocate GPU.
        Exit Snapshot is enabled by default. Idle timeout is calculated for
        each Sandbox based on a budget equal to 2 CPU-core-hours of Modal
        Sandbox compute (currently USD 0.283824), accounting for reserved
        CPU and RAM. The idle budget is not a total spending limit.
        Resource requests and image builds incur Modal charges.
        """
        require_authorized_owner()
        idle_policy = idle_budget_for(cpu, memory_mib, lifetime_seconds)
        selected_image, image_meta = resolve_sandbox_image(
            modal, sandbox_image, image_ref, image_source, image_add_python
        )
        # Explicit keepalive for registry images: since Modal now respects
        # OCI CMD, e.g. python:3.12's default CMD may exit immediately.
        keepalive = ("sh", "-c", "while :; do sleep 3600; done") if image_ref else ()
        sb = modal.Sandbox.create(
            *keepalive,
            app=app,
            image=selected_image,
            timeout=lifetime_seconds,
            idle_timeout=idle_policy["idle_seconds"],
            cpu=cpu,
            memory=memory_mib,
            workdir="/workspace" if persistent_workspace else "/tmp",
            volumes={"/workspace": WORKSPACE_VOLUME} if persistent_workspace else {},
            tags=managed_tags(cpu, memory_mib, lifetime_seconds, persistent_workspace),
            experimental_options={"enable_exit_snapshot": True},
        )
        try:
            return {
                "sandbox_id": sb.object_id,
                "status": "created",
                "lifetime_seconds": lifetime_seconds,
                "exit_snapshot_enabled": True,
                "idle_policy": idle_policy,
                "persistent_workspace": persistent_workspace,
                "workspace_path": "/workspace" if persistent_workspace else None,
                **image_meta,
            }
        finally:
            sb.detach()

    @mcp.tool
    def exec_command(sandbox_id: str, command: str, timeout_seconds: int = 30) -> dict:
        """Run a shell command in an existing sandbox. Results are size-limited."""
        require_authorized_owner()
        if not command or len(command) > 8000:
            raise ValueError("command must contain 1–8000 characters")
        if not 1 <= timeout_seconds <= MAX_COMMAND_SECONDS:
            raise ValueError(f"timeout_seconds must be 1–{MAX_COMMAND_SECONDS}")
        sb = _get_sandbox(sandbox_id)
        try:
            # Maintain Bash behavior where available; permit POSIX images
            # that provide /bin/sh but do not include Bash (e.g. Alpine).
            proc = sb.exec(
                "sh", "-c",
                'if command -v bash >/dev/null 2>&1; then exec bash -lc "$1"; '
                'else exec sh -c "$1"; fi',
                "mcp-shell", command, timeout=timeout_seconds,
            )
            stdout = proc.stdout.read()
            stderr = proc.stderr.read()
            return {
                "exit_code": proc.wait(),
                "stdout": _clip(stdout),
                "stderr": _clip(stderr),
            }
        finally:
            sb.detach()

    @mcp.tool
    def read_path(
        sandbox_id: str,
        path: str,
        expires_in_seconds: int = 600,
    ) -> dict:
        """Read a Sandbox path without offsets or large MCP responses.

        Small UTF-8 text (up to 8192 bytes) is returned inline. Large or
        binary files yield a signed HTTPS download link. Directories are
        exported as a ZIP with a signed download link. URLs expire after
        expires_in_seconds (60–3600); use revoke_download_link to revoke.
        """
        require_authorized_owner()
        path = safe_path(path)
        sb = _get_sandbox(sandbox_id)
        try:
            decision = inspect_path(sb.filesystem, path)
        finally:
            sb.detach()
        if decision["delivery"] == "inline":
            return decision
        staged = stage_download(
            sandbox_id, path, expires_in_seconds,
            archive_directory=decision["kind"] == "directory",
        )
        return {
            **decision,
            **staged,
            "delivery": "download",
            "kind": decision["kind"],
        }

    @mcp.tool
    def write_file(sandbox_id: str, path: str, content: str) -> dict:
        """Write one UTF-8 file in the sandbox (100 KiB maximum)."""
        require_authorized_owner()
        if not path.startswith("/") or len(path) > 1024:
            raise ValueError("path must be absolute")
        data = content.encode("utf-8")
        if len(data) > MAX_FILE_CHARS:
            raise ValueError("File is too large")
        sb = _get_sandbox(sandbox_id)
        try:
            import posixpath

            sb.filesystem.make_directory(posixpath.dirname(path))
            sb.filesystem.write_bytes(data, path)
            return {"path": path, "bytes_written": len(data)}
        finally:
            sb.detach()

    @mcp.tool
    def sandbox_status(sandbox_id: str) -> dict:
        """Check whether a sandbox is running or has exited."""
        require_authorized_owner()
        sb = _get_sandbox(sandbox_id)
        try:
            code = sb.poll()
            return {"sandbox_id": sandbox_id, "running": code is None, "exit_code": code}
        finally:
            sb.detach()

    @mcp.tool
    def terminate_sandbox(sandbox_id: str) -> dict:
        """Stop this Sandbox and delete its Exit Snapshot when available.

        Modal automatically creates an Exit Snapshot even on terminate().
        Wait for the snapshot, then call experimental.image_delete to discard
        it. On errors, report not_deleted instead of claiming cleanup.
        """
        require_authorized_owner()
        sb = _get_sandbox(sandbox_id)
        try:
            tags = sb.get_tags()
            sb.terminate(wait=True)
            if tags.get("mcp_exit_snapshot") != "1":
                snapshot = {"status": "not_enabled", "deleted": False}
            else:
                snapshot = delete_exit_snapshot_of(sb, modal, timeout_seconds=45, snapshot_enabled=True)
            return {
                "sandbox_id": sandbox_id,
                "terminated": True,
                "exit_snapshot": snapshot,
            }
        finally:
            sb.detach()

    @mcp.tool
    def resume_sandbox(sandbox_id: str) -> dict:
        """Restore a Sandbox after an idle/lifetime timeout using Exit Snapshot.

        Returns a NEW sandbox_id; running processes are not resumed. This
        cannot restore manually terminated Sandboxes whose snapshot was
        successfully deleted. Snapshot retrieval may fail (Beta feature).
        """
        require_authorized_owner()
        previous = _get_sandbox(sandbox_id)
        try:
            if previous.poll() is None:
                raise ValueError("Sandbox is still running; no Exit Snapshot exists yet")
            tags = previous.get_tags()
            cpu, memory_mib, lifetime_seconds, persistent = restored_settings(tags)
            snapshot_image = previous._experimental_get_exit_snapshot(timeout=45)
        finally:
            previous.detach()

        idle_policy = idle_budget_for(cpu, memory_mib, lifetime_seconds)
        sb = modal.Sandbox.create(
            "sh", "-c", "while :; do sleep 3600; done",
            app=app,
            image=snapshot_image,
            timeout=lifetime_seconds,
            idle_timeout=idle_policy["idle_seconds"],
            cpu=cpu,
            memory=memory_mib,
            workdir="/workspace" if persistent else "/tmp",
            volumes={"/workspace": WORKSPACE_VOLUME} if persistent else {},
            tags=managed_tags(cpu, memory_mib, lifetime_seconds, persistent),
            experimental_options={"enable_exit_snapshot": True},
        )
        try:
            return {
                "sandbox_id": sb.object_id,
                "restored_from_sandbox_id": sandbox_id,
                "source_snapshot_image_id": snapshot_image.object_id,
                "status": "created",
                "exit_snapshot_enabled": True,
                "idle_policy": idle_policy,
                "lifetime_seconds": lifetime_seconds,
                "persistent_workspace": persistent,
                "workspace_path": "/workspace" if persistent else None,
                "processes_restored": False,
            }
        finally:
            sb.detach()

    @mcp.tool
    def list_directory(
        sandbox_id: str, path: str, offset: int = 0, limit: int = 100
    ) -> dict:
        """List a paginated Sandbox directory without oversized MCP responses."""
        require_authorized_owner()
        path = safe_path(path)
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("offset must be nonnegative and limit 1–200")
        sb = _get_sandbox(sandbox_id)
        try:
            entries = sorted(sb.filesystem.list_files(path), key=lambda x: x.name)
            subset = entries[offset:offset+limit]
            return {
                "path": path,
                "total": len(entries),
                "next_offset": offset + limit if offset + limit < len(entries) else None,
                "entries": [{
                    "name": x.name, "type": str(x.type),
                    "size_bytes": x.size
                } for x in subset],
            }
        finally:
            sb.detach()

    @mcp.tool
    def stat_path(sandbox_id: str, path: str) -> dict:
        """Get file size and type without reading its contents."""
        require_authorized_owner()
        path = safe_path(path)
        sb = _get_sandbox(sandbox_id)
        try:
            info = sb.filesystem.stat(path)
            return {"path": path, "name": info.name,
                    "type": str(info.type), "size_bytes": info.size}
        finally:
            sb.detach()

    @mcp.tool
    def make_directory(sandbox_id: str, path: str) -> dict:
        """Create a directory and any missing parent directories."""
        require_authorized_owner()
        path = safe_path(path)
        sb = _get_sandbox(sandbox_id)
        try:
            sb.filesystem.make_directory(path, create_parents=True)
            return {"path": path, "created": True}
        finally:
            sb.detach()

    @mcp.tool
    def remove_path(sandbox_id: str, path: str, recursive: bool = False) -> dict:
        """Delete a file or directory; recursive deletion is opt-in."""
        require_authorized_owner()
        path = safe_path(path)
        if path in ("/", "/workspace", "/tmp", "/home", "/root", "/usr", "/etc", "/var"):
            raise ValueError("Refusing to delete a protected root directory")
        sb = _get_sandbox(sandbox_id)
        try:
            sb.filesystem.remove(path, recursive=recursive)
            return {"path": path, "removed": True, "recursive": recursive}
        finally:
            sb.detach()

    @mcp.tool
    def commit_workspace(sandbox_id: str) -> dict:
        """Persist files modified in the optional /workspace Modal Volume."""
        require_authorized_owner()
        sb = _get_sandbox(sandbox_id)
        try:
            if sb.get_tags().get("mcp_persistent_workspace") != "1":
                raise ValueError("This Sandbox was not created with a persistent workspace")
            process = sb.exec("sync", "/workspace", timeout=60)
            result = process.wait()
            if result != 0:
                raise RuntimeError("Volume sync failed: " + _clip(process.stderr.read(), 300))
            return {"sandbox_id": sandbox_id, "volume": "modal-sandbox-mcp-workspace",
                    "path": "/workspace", "committed": True}
        finally:
            sb.detach()

    @mcp.tool
    def create_upload_link(
        sandbox_id: str, path: str, size_bytes: int, sha256: str,
        expires_in_seconds: int = 600,
    ) -> dict:
        """Create a signed PUT URL for binary upload, up to 256 MiB.

        The upload is streamed over HTTPS, checked against size/SHA-256 and
        copied into the Sandbox without sending its bytes through MCP.
        """
        require_authorized_owner()
        path = safe_path(path)
        sb = _get_sandbox(sandbox_id)
        try:
            if sb.poll() is not None:
                raise ValueError("Sandbox is no longer running")
        finally:
            sb.detach()
        return make_upload_link(sandbox_id, path, size_bytes, sha256,
                                expires_in_seconds)

    @mcp.tool
    def revoke_download_link(download_url: str) -> dict:
        """Immediately remove an exported file and invalidate its signed link."""
        require_authorized_owner()
        from urllib.parse import urlsplit
        parsed = urlsplit(download_url)
        prefix = "/transfer/download/"
        if parsed.netloc != urlsplit("https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run").netloc:
            raise ValueError("Not a Modal MCP download URL")
        if not parsed.path.startswith(prefix):
            raise ValueError("Not a download URL")
        return revoke_staged_download(parsed.path[len(prefix):])

    return mcp.http_app(stateless_http=True)
