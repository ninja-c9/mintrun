# Polyglot Plugin SDK

Because **everything in `mintrun` is a plugin**, any developer can extend `mintrun` with new third-party Vaults (`lastpass`, `bitwarden`, `hashicorp-vault`) or JIT Providers (`vercel`, `supabase`, `digitalocean`, `stripe`) in **any language** (Python, Bash, Node.js, Go, Rust) without recompiling the binary. External plugins cannot override built-in plugin names.

Three working plugins ship in [`examples/plugins/`](../examples/plugins/README.md) and are built into the binary: a `bitwarden` vault, and `vercel` and `postgres-jit` providers. `mintrun plugin install <name>` installs one with no clone or download.

## Managing Plugins

```bash
# List all built-in and installed external plugins
./mintrun plugin list

# Install a plugin built into the binary by name: bitwarden, vercel, or postgres-jit
./mintrun plugin install bitwarden

# Install from a local directory containing plugin.json + executable entrypoint.
# Give it as a path: a bare name built into the binary installs the built-in copy,
# never a directory of that name in the current directory.
./mintrun plugin install ./examples/plugins/bitwarden

# Install a single-file remote plugin bundle over HTTPS with mandatory out-of-band SHA-256 pinning
./mintrun plugin install "https://registry.example.com/plugins/bitwarden.json#sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Use an installed external vault for a single command or as the default vault
./mintrun exec -vault bitwarden -provider cloudflare -scope example.com -perms dns:write,workers:write -- npx wrangler deploy
export MINTRUN_VAULT=bitwarden

# Remove an external plugin
./mintrun plugin remove bitwarden
```

## Writing an External Plugin (`stdin` $\rightarrow$ `stdout` JSON Protocol)

Place a `plugin.json` manifest and an executable entrypoint inside `~/.mintrun/plugins/<name>/` (or publish a single-file JSON bundle with `"script"` for remote installation):

**1. `plugin.json`** (from [`examples/plugins/vercel`](../examples/plugins/vercel/plugin.json))
```json
{
  "name": "vercel",
  "version": "0.1.0",
  "kind": "provider",
  "description": "Mints a Vercel token that expires with the lease and deletes it on exit",
  "entrypoint": "run",
  "scopes": ["<project_id>", "<team_id>/<project_id>"]
}
```

**2. Request Payload (`stdin` to `entrypoint`)**
```json
{
  "op": "mint",
  "master_secret": "<resolved-from-vault>",
  "mint_request": {
    "provider": "vercel",
    "scope": "team_abc/prj_def",
    "ttl_seconds": 900
  }
}
```
*(For a `"kind": "vault"` plugin such as [`bitwarden`](../examples/plugins/bitwarden/run), `mintrun` sends `"op": "get_secret"`, `"set_secret"`, or `"delete_secret"` with `"key"` and `"value"`, and expects `{"value": "..."}` on `stdout`.)*

**3. Response Payload (`stdout` from `entrypoint`)**
```json
{
  "lease": {
    "id": "<vercel-token-id>",
    "provider": "vercel",
    "scope": "team_abc/prj_def",
    "env": {
      "VERCEL_TOKEN": "<new-bearer-token>"
    },
    "redact": ["<new-bearer-token>"],
    "expires_at": "2026-10-16T10:15:00Z",
    "ephemeral": true
  }
}
```

When the child command finishes, `mintrun` invokes your provider plugin again with `{"op": "revoke", "master_secret": "...", "lease": {...}}` so it can invalidate the token. If the token cannot be invalidated early and can only expire, reply `{"error": "..."}`, and `mintrun` reports `revoked: false`.

Put only secrets in `env`. `mintrun` removes every `env` value, every `redact` entry, and the lease `id` from the command's output, so a non-secret such as a port number would be blanked wherever it appears. The `id` is public: the audit log and the MCP result show it.

A reply that does not decode, such as text that is not JSON or an `expires_at` that is not an RFC 3339 time, fails with `plugin "<name>" returned an invalid JSON response`. `mintrun` never quotes the reply, because it can hold a secret.
