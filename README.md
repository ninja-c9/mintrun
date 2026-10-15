# mintrun

**Zero-knowledge JIT credential minter & blind CLI runner for AI Agents.**
**Everything is a plugin.**

`mintrun` lets you grant master credentials (like a Cloudflare Master Token, GitHub App key, or 1Password Vault) once to your machine's native vault. AI Agents (Antigravity, Claude Code, Cursor) never see or hold raw API keys: `mintrun` dynamically mints short-lived, resource-scoped sub-tokens, injects them into child CLI processes (`wrangler`, `gh`, `terraform`, `curl`), scrubs any accidental leaks from `stdout`/`stderr`, and immediately revokes the ephemeral lease when the command exits.

---

## Architecture (`Everything is a Plugin`)

`mintrun` has a tiny, zero-dependency Go core runtime built around 3 plugin kinds (`internal/core/plugin.go`):

| Plugin Kind | Role | Built-in / Examples |
| :--- | :--- | :--- |
| **`vault`** | Stores & retrieves master secrets outside agent context | `keychain` (macOS `/usr/bin/security` + `0600` local fallback), `1password`, `openbao` |
| **`provider`** | Mints & revokes JIT ephemeral credentials from a master secret | `cloudflare` (`POST /client/v4/user/tokens` + zone lock + `DELETE` revoke), `github`, `aws-sts` |
| **`bridge`** | Exposes the runtime to AI agents | `mcp` (Model Context Protocol JSON-RPC 2.0 over stdio) |

---

## Quick Start

### 1. Build & Store Cloudflare Master Token
```bash
go build -o mintrun ./cmd/mintrun

# Store your Cloudflare API Token (with "User API Tokens: Edit" permission for JIT minting)
./mintrun secret set cloudflare
./mintrun secret check cloudflare
```

### 2. Run a CLI Command Blindly (Zero Secret Exposure)
```bash
# Mints a sub-token locked to zone `example.com`, runs `wrangler deploy`, scrubs stdout/stderr, and revokes the sub-token on exit:
./mintrun exec -provider cloudflare -scope example.com -perms dns:write,workers:write -- npx wrangler deploy
```

### 3. Connect to Antigravity / Claude Code (MCP Server)
Add `mintrun` to your MCP configuration:
```json
{
  "mcpServers": {
    "mintrun": {
      "command": "/path/to/mintrun",
      "args": ["mcp"]
    }
  }
}
```
Your AI agent can now call `mintrun_exec` and `mintrun_plugins` without ever asking you for API keys or seeing raw secrets.

---

## Writing & Installing External Plugins (Any Language)

Any executable or script can be installed as a `mintrun` plugin into `~/.mintrun/plugins/<name>/` via a `plugin.json` manifest and a JSON-over-stdio entrypoint:

```bash
./mintrun plugin list
./mintrun plugin install ./path/to/my-plugin
./mintrun plugin install https://registry.example.com/plugins/github.json
./mintrun plugin remove github
```

### External Plugin Protocol (`stdin` $\rightarrow$ `stdout` JSON)
- **Manifest (`plugin.json`):**
  ```json
  {
    "name": "github",
    "version": "0.1.0",
    "kind": "provider",
    "description": "GitHub App Installation Token Minter",
    "entrypoint": "run",
    "scopes": ["repo:read", "contents:write"]
  }
  ```
- **Mint Request (`stdin`):**
  ```json
  {
    "op": "mint",
    "master_secret": "<resolved-from-vault>",
    "mint_request": {
      "provider": "github",
      "scope": "owner/repo",
      "permissions": ["contents:write"],
      "ttl_seconds": 600
    }
  }
  ```
- **Mint Response (`stdout`):**
  ```json
  {
    "lease": {
      "id": "lease-123",
      "provider": "github",
      "env": { "GITHUB_TOKEN": "ghs_short_lived_token" },
      "redact": ["ghs_short_lived_token"],
      "ephemeral": true
    }
  }
  ```
