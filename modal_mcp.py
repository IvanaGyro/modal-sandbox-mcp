"""An authenticated, serverless MCP control plane for Modal Sandboxes.

Deployment: modal deploy modal_mcp.py
"""

from __future__ import annotations

import os

import modal
from oauth_support import AUTH_VOLUME, github_oauth, require_authorized_owner

APP_NAME = "modal-sandbox-mcp"
app = modal.App(APP_NAME)

# The web app and the sandbox use separate images. A web request never executes
# arbitrary user commands in the control-plane container.
web_image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "fastmcp>=3.4,<3.5", "pydantic>=2,<3"
).add_local_python_source("oauth_support").add_local_python_source("passphrase_oauth")
sandbox_image = modal.Image.debian_slim(python_version="3.12").apt_install(
    "bash", "git", "curl", "ca-certificates", "build-essential"
)

MAX_COMMAND_SECONDS = 45
MAX_OUTPUT_CHARS = 24_000
MAX_FILE_CHARS = 100_000


def _auth_from_environment():
    """Fail closed: never deploy a publicly accessible unauthenticated shell."""
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
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
        # For local integration with a bearer-capable MCP client only.
        # StaticTokenVerifier is NOT a production OAuth implementation.
        token = os.getenv("MCP_DEV_BEARER_TOKEN", "")
        if len(token) < 32:
            raise RuntimeError("MCP_DEV_BEARER_TOKEN must be at least 32 characters")
        return StaticTokenVerifier(tokens={token: {"client_id": "private-dev-client", "scopes": ["sandbox"]}})
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
    volumes={"/oauth-state": AUTH_VOLUME},
)
@modal.concurrent(max_inputs=8)
@modal.asgi_app()
def mcp_web():
    """FastMCP handles MCP protocol, OAuth metadata and HTTP sessions."""
    from fastmcp import FastMCP

    auth_provider = _auth_from_environment()
    mcp = FastMCP("Modal Sandbox MCP", auth=auth_provider)

    if os.getenv("MCP_AUTH_MODE", "").strip().lower() == "passphrase":
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
            workdir="/tmp",
        )
        try:
            return {"sandbox_id": sb.object_id, "status": "created", "lifetime_seconds": lifetime_seconds}
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
    def read_file(sandbox_id: str, path: str) -> dict:
        """Read a UTF-8 text file from a sandbox, up to 100 KiB."""
        require_authorized_owner()
        if not path.startswith("/") or len(path) > 1024:
            raise ValueError("path must be absolute")
        sb = _get_sandbox(sandbox_id)
        try:
            # Modal's filesystem API avoids subprocess argv-size limits and
            # shell quoting problems when transferring files.
            data = sb.filesystem.read_bytes(path)
            if len(data) > MAX_FILE_CHARS:
                raise ValueError("File is too large")
            return {"path": path, "content": data.decode("utf-8")}
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

    return mcp.http_app(stateless_http=True)
