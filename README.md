# Modal Sandbox MCP — self-hosted OAuth + ChatGPT

A serverless, authenticated MCP server on Modal that can start isolated Linux
Sandboxes and execute commands. **Modal hosts both the MCP resource server and
the OAuth authorization server. No Cloudflare Worker or GitHub OAuth App is
required.**

## Verified deployment

- MCP URL: `https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/mcp`
- Authorization server discovery: `https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/.well-known/oauth-authorization-server`
- Protected resource metadata: `https://ivanagyro--modal-sandbox-mcp-mcp-web.us-east.modal.run/.well-known/oauth-protected-resource/mcp`
- [Modal deployment](https://modal.com/apps/ivanagyro/main/deployed/modal-sandbox-mcp)
- [Live OAuth + tool execution test](https://github.com/IvanaGyro/modal-sandbox-mcp/actions/runs/43817281535)
- [Self-hosted OAuth unit/integration and CIMD tests](https://github.com/IvanaGyro/modal-sandbox-mcp/actions/runs/43816578216)
- [Encrypted Modal Volume cross-container recovery](https://github.com/IvanaGyro/modal-sandbox-mcp/actions/runs/43816784810)

The live test fetched ChatGPT's published CIMD metadata, ran the authorization
code flow with a passphrase and S256 PKCE, obtained an OAuth bearer token,
listed all six tools, then created a Sandbox, ran a shell command and terminated
the Sandbox. **A real ChatGPT plugin login has not yet been performed through
ChatGPT's user interface.**

## Connect from ChatGPT

1. Open ChatGPT **on the web** → **Plugins** → **Add custom MCP server**.
2. Enter `Modal Sandbox MCP`, and the MCP URL above.
3. Select **OAuth**. Prefer **Client ID Metadata Documents (CIMD)**; **DCR**
   is supported as a fallback. No pre-defined OAuth Client ID or Client Secret
   is required. The discovery metadata advertises public-client
   `token_endpoint_auth_methods_supported: ["none", ...]` and S256 PKCE.
4. When the server displays **Authorize Modal Sandbox MCP**, enter your private
   passphrase *in that HTTPS consent screen only* and approve.
5. Complete the ChatGPT connection and test `tools/list`, then a small
   `create_sandbox` → `exec_command` → `terminate_sandbox` sequence.

**Current bootstrap mode:** `MCP_AUTH_MODE=static-dev` is configured in the
existing Modal Secret `modal-mcp-auth`. The existing high-entropy
`MCP_DEV_BEARER_TOKEN` is temporarily used **both** as the OAuth consent
passphrase **and** as a legacy bearer for the previously tested clients. You
need your saved copy of that token to enter the consent screen. Do not put it
in chat, source, environment files committed to git, or GitHub Actions logs.

Use an independent passphrase and disable legacy bearer once connected:

```dotenv
MCP_AUTH_MODE=passphrase
MCP_AUTH_PASSPHRASE=<new random string, at least 32 characters>
```

Set these values in the **Modal Secret**, not GitHub Secrets. Remove
`MCP_DEV_BEARER_TOKEN` in final passphrase mode. Changing the passphrase also
changes the current Fernet encryption key: the old encrypted OAuth state must
be reset and ChatGPT re-authorized. Coordinate this before rotating the secret
to avoid temporarily disabling the server.

In permanent `passphrase` mode, no legacy static bearer is accepted.
OAuth access tokens are bound to the MCP resource URI, owner subject and
required `sandbox` scope.

## OAuth flow and design

```text
ChatGPT (OAuth client, CIMD or DCR)
   → Modal /authorize → Modal /consent (passphrase)
   → Modal /token (S256 PKCE code exchange)
   → Modal /mcp (resource-bound access token)
   → Modal Sandbox (isolated Linux execution)
```

The server uses the FastMCP v3 OAuth base implementation for DCR, authorization
code exchange, PKCE validation, token refresh and revocation. The custom
PassphraseOAuthProvider adds interactive, fail-closed consent and durable,
encrypted persistence.

- CIMD clients are fetched with FastMCP's SSRF-resistant CIMD fetcher and
  constrained to `https://chatgpt.com/oauth/.../client.json` and HTTPS
  `chatgpt.com` callback URIs.
- DCR clients must register HTTPS `chatgpt.com` callback URIs.
- A passphrase is required for authorization. Incorrect attempts are limited
  per consent handle. The form uses a short-lived CSRF nonce and secure
  HttpOnly SameSite cookie.
- One-use authorization codes, S256 PKCE, short-lived access tokens and rotated
  refresh tokens are handled by the MCP SDK; refresh tokens expire after 30 days.
- Registrations, tokens and pending grants are Fernet encrypted and committed
  to a persistent Modal Volume. A single ASGI container avoids simultaneous
  writers. The passphrase-derived key is intentionally not stored in GitHub.
- No unauthenticated access to `/mcp` is allowed.

**Security limitation:** This is a personal, experimental authorization
server, not an audited general-purpose identity provider. It cannot prove a
request originated from ChatGPT by DCR alone; it relies on the passphrase.
For production-grade access controls, consider mTLS, external IdP, a
dedicated encryption key, rate limits and additional auditing.

## MCP tools

| Tool | Function |
|---|---|
| `create_sandbox` | CPU-only Linux Sandbox, optionally mount shared persistent `/workspace` |
| `exec_command` | Shell command, up to 45 seconds per call |
| `read_file` | UTF-8 byte-range reader, **8 KiB default / 16 KiB maximum** per result |
| `write_file` | UTF-8 text file write, up to 100,000 bytes |
| `list_directory` | Paginated directory entries (up to 200 per call) |
| `stat_path` | File/directory type and size |
| `make_directory` | Create nested directories |
| `remove_path` | Delete file/directory (recursive deletion opt-in) |
| `commit_workspace` | Commit changes to the shared persistent `/workspace` Volume |
| `create_upload_link` | Short-lived signed HTTPS PUT for binary files up to **256 MiB** |
| `create_download_link` | Snapshot Sandbox file to a persistent staging Volume; signed HTTPS GET |
| `create_directory_download_link` | Package a directory into ZIP, return signed HTTPS GET |
| `revoke_download_link` | Immediately delete staged export and invalidate its URL |
| `sandbox_status` | Check running state |
| `terminate_sandbox` | Stop sandbox computation |

**MCP never returns large file contents:** only short metadata/URLs. For plain
text, `read_file(sandbox_id, path, offset=0, max_bytes=8192)` returns
`content`, `size_bytes`, `offset`, `next_offset` and `eof`. Use its
returned `next_offset` to avoid splitting UTF-8 sequences. For a binary file
or larger payload, prefer a signed link instead of Base64 in MCP.

### Binary upload (e.g. a 100 MiB file)

1. Use MCP `create_sandbox` and keep the returned `sandbox_id`.
2. Compute the file's SHA-256 and number of **bytes** on your machine.
3. Call `create_upload_link(sandbox_id, path="/tmp/data.bin", size_bytes=..., sha256="...")`.
4. Upload the **raw file bytes** (not multipart form data) to `upload_url`:

```bash
# The URL is a short-lived bearer capability. Never log or share it.
curl --fail-with-body --request PUT \
  --header 'Content-Type: application/octet-stream' \
  --upload-file data.bin "$UPLOAD_URL"
```

The endpoint streams the body, checks exact file length and SHA-256, then
uses Modal's `Sandbox.filesystem.copy_from_local` to place the file into the
Sandbox. A successfully used upload URL cannot be reused. No large data is
sent through an MCP tool result.

### Binary download and directory archives

1. Call `create_download_link(sandbox_id, "/tmp/data.bin")`, or
   `create_directory_download_link(sandbox_id, "/workspace/project")` for ZIP.
2. Fetch `download_url` via ordinary HTTPS:

```bash
curl --fail --location "$DOWNLOAD_URL" --output data.bin
sha256sum data.bin  # compare with SHA-256 from the MCP result
```

A download URL expires in **10 minutes by default** (configurable from 60 to
3600 seconds). The server snapshots the file into the private
`modal-sandbox-mcp-transfer-cache` Volume. Exports are limited to 256 MiB
each, 20 retained files, and a 1 GiB staging quota. URLs can be revoked with
`revoke_download_link`, and expired staged exports are cleaned hourly.
Anyone with the URL can download until it expires; treat the URL like a secret.

### Persistent workspace

Specify `persistent_workspace=True` in `create_sandbox` to mount the shared
named Volume `modal-sandbox-mcp-workspace` at `/workspace`. Call
`commit_workspace(sandbox_id)` after changes to make them durable and visible
to other Sandboxes. This workspace is **shared by all persistent Sandboxes**,
not private to one session. Changes to identical filenames from concurrent
Sandboxes can conflict. The workspace survives Sandbox termination; `/tmp`
does not.

Sandbox lifetime is at most one hour, 2 CPU cores and 4 GiB of RAM.
The sample defaults are conservative. Sandboxes and Modal Volume storage may
consume paid resources. **Terminate Sandboxes when finished.**

## Deployment and testing

Store only the Modal deployment credentials in **GitHub Actions Secrets**:
`MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET`.

Store runtime authentication credentials in the **Modal Secret** named
`modal-mcp-auth`. The HTTP application uses that secret at runtime.
Pushes to `main` that change the server or deployment workflow deploy
automatically; you can also run
[Deploy to Modal](https://github.com/IvanaGyro/modal-sandbox-mcp/actions/workflows/deploy.yml)
manually.

Useful tests:

- `smoke_passphrase_oauth.py` — isolated DCR, consent, PKCE, token and refresh.
- `smoke_chatgpt_cimd.py` — fetch and validate ChatGPT's real CIMD metadata.
- `smoke_passphrase_volume.py` — encrypted Modal Volume commit and recovery.
- `smoke_live_oauth.py` — real endpoint, real OAuth, tools/list and Sandbox.
- `smoke_mcp.py` — legacy bearer, tool discovery and anonymous denial.
- `smoke_sandbox.py` — original six tool calls using the legacy bearer.
- `smoke_transfer_100mb.py` — 100 MiB HTTP PUT/GET SHA-256 roundtrip,
  ZIP directory export, paginated text read and cross-Sandbox Volume persistence.

Use GitHub Actions `workflow_dispatch` for the expensive integration tests.
The full OAuth suite is manual to avoid repeated Modal App-create rate limits.
The ordinary `Check` workflow performs lightweight syntax and unit checks.

## References

- [OpenAI: plugin authentication](https://developers.openai.com/plugins/build/auth)
- [FastMCP: full OAuth server](https://gofastmcp.com/servers/auth/full-oauth-server)
- [FastMCP: HTTP deployment](https://gofastmcp.com/deployment/http)
- [Modal: Sandbox API](https://modal.com/docs/sdk/py/latest/Sandbox)
- [Modal: volumes](https://modal.com/docs/guide/volumes)
