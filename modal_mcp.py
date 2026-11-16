"""An authenticated, serverless MCP control plane for Modal Sandboxes.

Deployment: modal deploy modal_mcp.py
"""

from __future__ import annotations

import os

import modal
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
).add_local_python_source("oauth_support").add_local_python_source("passphrase_oauth").add_local_python_source("transfer_http")
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
        lifetime_seconds: int = 1800,
        idle_seconds: int = 300,
        cpu: float = 1.0,
        memory_mib: int = 1024,
        persistent_workspace: bool = False,
    ) -> dict:
        """Create an isolated Linux shell. Resource requests incur Modal charges."""
        require_authorized_owner()
        if not 60 <= lifetime_seconds <= 3600:
            raise ValueError("lifetime_seconds must be 60–3600")
        if not 30 <= idle_seconds <= lifetime_seconds:
            raise ValueError("idle_seconds must be 30–lifetime_seconds")
        if not 0.125 <= cpu <= 2:
            raise ValueError("cpu must be 0.125–2 cores")
        if not 128 <= memory_mib <= 4096:
            raise ValueError("memory_mib must be 128–4096")
        sb = modal.Sandbox.create(
            app=app,
            image=sandbox_image,
            timeout=lifetime_seconds,
            idle_timeout=idle_seconds,
            cpu=cpu,
            memory=memory_mib,
            workdir="/workspace" if persistent_workspace else "/tmp",
            volumes={"/workspace": WORKSPACE_VOLUME} if persistent_workspace else {},
        )
        try:
            return {
                "sandbox_id": sb.object_id,
                "status": "created",
                "lifetime_seconds": lifetime_seconds,
                "persistent_workspace": persistent_workspace,
                "workspace_path": "/workspace" if persistent_workspace else None,
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
            proc = sb.exec("bash", "-lc", command, timeout=timeout_seconds)
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
    def read_file(
        sandbox_id: str,
        path: str,
        offset: int = 0,
        max_bytes: int = 8192,
    ) -> dict:
        """Read a bounded UTF-8 byte range; use next_offset to continue.

        Defaults to 8 KiB rather than returning whole files into ChatGPT.
        For binary files or large downloads use create_download_link.
        """
        require_authorized_owner()
        path = safe_path(path)
        if offset < 0:
            raise ValueError("offset must be nonnegative")
        if not 256 <= max_bytes <= 16384:
            raise ValueError("max_bytes must be 256–16384")
        code = (
            "import codecs,json,os,sys;"
            "p=sys.argv[1];start=int(sys.argv[2]);n=int(sys.argv[3]);"
            "f=open(p,'rb');f.seek(start);part=f.read(n);"
            "dec=codecs.getincrementaldecoder('utf-8')(errors='strict');"
            "text=dec.decode(part,final=False);"
            "used=len(part)-len(dec.getstate()[0]);"
            "size=os.fstat(f.fileno()).st_size;"
            "print(json.dumps(dict(content=text,offset=start,next_offset=start+used,"
            "size_bytes=size,eof=start+used>=size),ensure_ascii=False))"
        )
        sb = _get_sandbox(sandbox_id)
        try:
            process = sb.exec(
                "python", "-c", code, path, str(offset), str(max_bytes), timeout=15
            )
            output = process.stdout.read()
            error = process.stderr.read()
            code = process.wait()
            if code != 0:
                raise RuntimeError("Cannot read UTF-8 chunk; verify offset and encoding: " + _clip(error, 600))
            return {"path": path, **__import__("json").loads(output)}
        finally:
            sb.detach()

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
        """Terminate a sandbox to stop its compute usage."""
        require_authorized_owner()
        sb = _get_sandbox(sandbox_id)
        try:
            sb.terminate()
            return {"sandbox_id": sandbox_id, "terminated": True}
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
            probe = sb.exec("mountpoint", "-q", "/workspace", timeout=15)
            if probe.wait() != 0:
                raise ValueError("This Sandbox has no persistent /workspace Volume")
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
    def create_download_link(
        sandbox_id: str, path: str, expires_in_seconds: int = 600,
    ) -> dict:
        """Stage a snapshot of a Sandbox file and return a short-lived HTTPS GET."""
        require_authorized_owner()
        return stage_download(sandbox_id, path, expires_in_seconds)

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
