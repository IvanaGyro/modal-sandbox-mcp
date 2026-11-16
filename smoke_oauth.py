"""Offline GitHub OAuth configuration smoke test, without real credentials."""
import os
import modal
from oauth_support import AUTH_VOLUME, github_oauth

app = modal.App("modal-mcp-oauth-configuration-smoke")
image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "fastmcp>=3.4,<3.5", "pydantic>=2,<3"
).add_local_python_source("oauth_support")


@app.function(image=image, volumes={"/oauth-state": AUTH_VOLUME}, timeout=120)
def verify_github_oauth_configuration() -> list[str]:
    # Fake values validate only construction and route advertisement.
    # No real user login, OAuth code exchange or issued token is involved.
    os.environ["GITHUB_CLIENT_ID"] = "dummy-oauth-client-id"
    os.environ["GITHUB_CLIENT_SECRET"] = "dummy-secret-for-route-testing"
    os.environ["MCP_OAUTH_SIGNING_KEY"] = "testing-only-signing-key-not-for-production-0123456789"
    from fastmcp import FastMCP
    provider = github_oauth()
    service = FastMCP("OAuth configuration smoke", auth=provider)
    asgi = service.http_app(stateless_http=True)
    paths = sorted(set(str(getattr(route, "path", "")) for route in asgi.routes))
    assert any("authorize" in path for path in paths), paths
    assert any("register" in path for path in paths), paths
    print("GitHub OAuth proxy initialization: OK")
    print("OAuth operational endpoints:", paths)
    return paths


@app.local_entrypoint()
def main():
    verify_github_oauth_configuration.remote()
