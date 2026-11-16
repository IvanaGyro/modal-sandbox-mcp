# Modal Sandbox MCP

A serverless, **authenticated** Streamable HTTP MCP server that manages isolated Modal Linux Sandboxes. It is deployable with GitHub Actions; no separate VPS is necessary.

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
4. In Modal, create or edit the secret named `modal-mcp-auth` using one of the authentication modes below.
5. Push changes to `main` to auto-deploy, or use **Actions → Deploy to Modal → Run workflow**.
6. Look up the resulting `mcp_web` HTTP URL in Modal deploy output. The MCP URL is that base URL plus `/mcp`.
7. Connect an MCP client with OAuth support. Note that compatibility with ChatGPT's custom connectors requires an OAuth provider that supports the client's flow; **deployment alone does not mean ChatGPT connection is tested**.

### Recommended: GitHub OAuth (ChatGPT compatible)

FastMCP's built-in `GitHubProvider` acts as an OAuth proxy and supplies MCP-compatible discovery, Dynamic Client Registration (DCR), authorization-code/PKCE, and JWT access tokens. The MCP server **also checks the signed-in GitHub login on every tool invocation**; authenticating as a different GitHub user does not grant shell access.

**The existing static-dev mode remains active until you update the Modal Secret.** The server cannot perform a real GitHub sign-in without the OAuth App credentials created in your account.

1. Open [GitHub → Developer settings → OAuth Apps](https://github.com/settings/developers) and select **New OAuth App**.
2. Enter:
   - Application name: `Modal Sandbox MCP`
   - Homepage URL: `https://github.com/IvanaGyro/modal-sandbox-mcp`
   - **Authorization callback URL:** `https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/auth/callback` (do NOT append `/mcp`)
3. Create the OAuth App and generate a Client Secret. **Do not put either credential in the repository or in ChatGPT.**
4. Edit the existing [Modal Secret `modal-mcp-auth`](https://modal.com/secrets) to set:

```dotenv
MCP_AUTH_MODE=github
GITHUB_CLIENT_ID=<from GitHub OAuth App>
GITHUB_CLIENT_SECRET=<from GitHub OAuth App>
MCP_OAUTH_SIGNING_KEY=<random secret string with at least 32 characters>
MCP_GITHUB_ALLOWED_LOGIN=IvanaGyro
MCP_BASE_URL=https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run
```

Generate a fresh signing key with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Keep it private and stable. Rotating this signing key invalidates current OAuth access tokens and the encrypted token store. Remove `MCP_DEV_BEARER_TOKEN` when you leave `static-dev`.

5. Redeploy with [Deploy to Modal](https://github.com/IvanaGyro/modal-sandbox-mcp/actions/workflows/deploy.yml) or push a change to the deployment workflow; an updated Secret alone may not restart an existing container.
6. Check `https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource/mcp`. The CI workflow validates these in GitHub mode.
7. On **ChatGPT web** (subject to workspace and plan permissions), visit Plugins → **Add custom MCP server**, supply `https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp`, choose OAuth with DCR, and complete **Sign in with GitHub**. Only `IvanaGyro` can execute the six Sandbox tools after login.

**State persistence:** FastMCP client registrations and tokens are encrypted with Fernet and stored on a Modal Volume. The server runs with one ASGI container to avoid concurrent writers to that file store; changes are committed after each mutation. This avoids the short-lived filesystem state of a cold-started serverless container. The volume and service may incur small charges.

**Testing:** `smoke_oauth.py` validates OAuth provider construction with fake values, not a real GitHub login. `smoke_sandbox.py` exercises all six tools through the real static-development bearer and always terminates the test sandbox.

### Alternative: External JWT OAuth provider

If an established IdP already supports the MCP authorization discovery requirements and issues audience-bound JWT tokens, the old `MCP_AUTH_MODE=oauth` option remains available. In this mode **`MCP_ALLOWED_SUB` is mandatory** for granting shell access, and the existing `MCP_JWKS_URI`, `MCP_ISSUER`, `MCP_AUDIENCE`, `MCP_AUTHORIZATION_SERVER`, `MCP_BASE_URL` settings are required.

### External JWT OAuth example

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

## Deploy manually or with GitHub Actions

On a machine with access to PyPI and a Modal account:

```bash
python -m pip install 'modal>=1.6,<2'
modal setup
modal deploy modal_mcp.py
```

Alternatively run the GitHub Actions deployment, after creating both GitHub and Modal secrets.

## Cost and safety

- The MCP control plane scales to zero when idle; running Sandboxes and stored OAuth Volume data consume paid resources.
- `create_sandbox` caps lifetime at 1 hour, idle time at up to that lifetime, 2 CPU cores, and 4 GiB memory.
- Sandbox IDs are returned to the client. **Keep them**; request-local memory is not persistent.
- Terminate Sandboxes when finished. Set Modal workspace budget alerts and spending limits.
- Do not pass Modal deployment credentials, GitHub PATs or unrelated secrets into general-purpose Sandboxes.
- Do not disable authentication on this public web endpoint: it grants arbitrary code execution in your Modal account.

## Source documentation

- [Modal GitHub Actions deployment](https://modal.com/docs/guide/useful-snippets)
- [Modal Sandbox Python API](https://modal.com/docs/sdk/py/latest/Sandbox)
- [Modal ASGI apps](https://modal.com/docs/guide/webhooks)
- [FastMCP GitHub OAuth](https://gofastmcp.com/docs/integrations/github)
- [FastMCP OAuth proxy](https://gofastmcp.com/docs/servers/auth/oauth-proxy)
- [FastMCP remote OAuth](https://gofastmcp.com/docs/servers/auth/remote-oauth)
- [FastMCP HTTP](https://gofastmcp.com/docs/deployment/http)