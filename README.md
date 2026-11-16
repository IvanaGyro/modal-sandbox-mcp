# Modal Sandbox MCP

A private, serverless, **authenticated** Streamable HTTP MCP server that manages isolated Modal Linux Sandboxes. It is deployable with GitHub Actions; no separate VPS is necessary.

## Tools

| Tool | Purpose |
|---|---|
| `create_sandbox` | Start a Linux shell with bounded CPU, RAM, lifetime and idle timeout |
| `exec_command` | Run a short Shell command with bounded output |
| `read_file` / `write_file` | Transfer small UTF-8 files via the Modal Sandbox filesystem API |
| `sandbox_status` | Check whether a sandbox is running |
| `terminate_sandbox` | Stop sandbox compute charges |

**Limitations:** Shell commands have a 45-second maximum. Jobs needing longer runtimes, GPU-specific images, bulk file transfer, durable volumes and cost caps need additional implementation. The server and its sandboxes may incur Modal charges. It is a starter project, not an audited multi-tenant service.

## Initial setup

1. Create a **private** repository named `modal-sandbox-mcp` in your GitHub account, or upload this project to any private GitHub repository. Verify its visibility in GitHub Settings; GitHub may default to public.
2. Register for Modal and obtain a scoped Modal API token.
3. Add GitHub Actions repository secrets `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET`. Do not commit tokens or share them in chat.
4. In Modal, create a secret named `modal-mcp-auth` with the **OAuth settings** described below.
5. Use **Actions → Deploy to Modal → Run workflow** (the deployment is intentionally manual).
6. Look up the resulting `mcp_web` HTTP URL in Modal deploy output. The MCP URL is that base URL plus `/mcp`.
7. Connect an MCP client with OAuth support. Note that compatibility with ChatGPT's custom connectors requires an OAuth provider that supports the client's flow; **deployment alone does not mean ChatGPT connection is tested**.

### Recommended: OAuth mode (production)

Create a Modal secret named `modal-mcp-auth` with all these environment variables:

```dotenv
MCP_AUTH_MODE=oauth
MCP_JWKS_URI=https://YOUR_IDP/.well-known/jwks.json
MCP_ISSUER=https://YOUR_IDP/
MCP_AUDIENCE=YOUR_RESOURCE_AUDIENCE
MCP_AUTHORIZATION_SERVER=https://YOUR_IDP/
MCP_BASE_URL=https://YOUR_MODAL_ENDPOINT.modal.run
```

Use a trusted identity provider that supports OAuth Dynamic Client Registration and JWT access tokens with the correct audience, for example a suitably configured WorkOS/Descope environment. Check issuer trailing slashes, resource audience and the real Modal endpoint precisely. The server exposes standards-based OAuth discovery using FastMCP's `RemoteAuthProvider`.

**OAuth credentials are for the MCP client; Modal's API token in GitHub Actions is used only to deploy the app.**

**Important bootstrap note:** Modal creates the HTTP URL during deployment. For an initial bootstrapping deployment, you may need to set `MCP_BASE_URL` from the expected endpoint, deploy, then update the Modal secret after learning the actual URL and redeploy. The endpoint must not be left available without valid authentication.

### Static bearer mode (development only)

For clients that can explicitly send an `Authorization: Bearer ...` HTTP header, create a Modal secret with:

```dotenv
MCP_AUTH_MODE=static-dev
MCP_DEV_BEARER_TOKEN=REPLACE_WITH_A_RANDOM_SECRET_LONGER_THAN_32_CHARACTERS
```

This uses FastMCP's `StaticTokenVerifier`, intended **only for development**, and does **not** implement OAuth discovery suitable for every ChatGPT client. Never use a short, guessable, or reused token. Prefer OAuth for long-lived deployment.

## Deploy manually

On a machine with access to PyPI and a Modal account:

```bash
python -m pip install 'modal>=1.6,<2'
modal setup
modal deploy modal_mcp.py
```

Alternatively run the GitHub Actions deployment, after creating both GitHub and Modal secrets.

## Cost and safety

- The MCP control plane scales to zero when idle; running Sandboxes consume paid resources.
- `create_sandbox` caps lifetime at 1 hour, idle time at up to that lifetime, 2 CPU cores, and 4 GiB memory.
- Sandbox IDs are returned to the client. **Keep them**; request-local memory is not persistent.
- Terminate Sandboxes when finished. Set Modal workspace budget alerts and spending limits.
- Do not pass Modal deployment credentials, GitHub PATs or unrelated secrets into general-purpose Sandboxes.
- Do not disable authentication on this public web endpoint: it grants arbitrary code execution in your Modal account.

## Source documentation

- [Modal GitHub Actions deployment](https://modal.com/docs/guide/useful-snippets)
- [Modal Sandbox Python API](https://modal.com/docs/sdk/py/latest/Sandbox)
- [Modal ASGI apps](https://modal.com/docs/guide/webhooks)
- [FastMCP remote OAuth](https://gofastmcp.com/docs/servers/auth/remote-oauth)
- [FastMCP HTTP](https://gofastmcp.com/docs/deployment/http)