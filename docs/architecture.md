# Architecture (`Everything is a Plugin`)

<div align="center">
  <img src="assets/bento-architecture.svg" alt="mintrun Modular Plugin Architecture" width="100%" />
</div>

`mintrun` is built around a tiny, zero-dependency Go kernel (`internal/core`) where secret storage, credential minting, and agent transport are pluggable contracts:

| Plugin Kind | Go Interface | Responsibility | Built-in Implementations |
| :--- | :--- | :--- | :--- |
| **`vault`** | `core.VaultPlugin` | Stores and retrieves long-lived master credentials outside agent context | • **`keychain`** — macOS Keychain (`/usr/bin/security -i`) or Linux libsecret (`secret-tool`), with the secret passed on `stdin` only, never `argv` (a macOS secret too long for one `security -i` line is split across up to 16 Keychain items behind a checksummed header, up to 24,000 bytes), plus an **AES-256-GCM** encrypted `0600` local fallback (`~/.mintrun/vault.json`); the fallback requires a **`MINTRUN_VAULT_KEY`** passphrase (PBKDF2-HMAC-SHA256 key, per-vault random salt), and a failing keystore call prints a warning before it is used. See [what the vault protects](security-model.md#5-what-the-vault-protects-and-what-it-does-not)<br />• **`1password`** — 1Password CLI (`op`) vault (`op://` URIs & `mintrun:<provider>` items); `secret set` pipes a JSON item template to `op item create` on `stdin` and archives older items with the same title |
| **`provider`** | `core.ProviderPlugin` | Mints short-lived, resource-scoped sub-tokens from a master secret and revokes them on exit where the API allows it | • **`cloudflare`** — Resolves domain names to Zone IDs, maps permissions (`dns:write`, `workers:write`), mints via `POST /client/v4/user/tokens`, and revokes via `DELETE /client/v4/user/tokens/{id}`<br />• **`github`** — Signs RS256 App JWTs (PKCS#1/PKCS#8), mints repo-scoped Installation Tokens (`GITHUB_TOKEN`, `GH_TOKEN`), and revokes via `DELETE /installation/token`<br />• **`aws`** — 100% stdlib SigV4 `STS AssumeRole` JIT minter for the role ARN given as the scope (`arn:aws:iam::<account_id>:role/<name>`), with inline session policy narrowing (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`); a session token in the master secret is signed with the request. STS credentials cannot be revoked early, so leases report `revoked: false` and live until their expiry, at least 15 min (the STS minimum duration)<br />• **`gcp`** — Signs an RS256 JWT bearer assertion (RFC 7523) from a service-account JSON key, exchanges it for an OAuth2 access token limited to the requested scopes (`cloud-platform.read-only`, `devstorage.read_only`, …), and injects `CLOUDSDK_AUTH_ACCESS_TOKEN` + `GOOGLE_OAUTH_ACCESS_TOKEN`. Revocation on exit is best-effort: Google does not revoke service-account tokens server-side, so they live until their fixed ≤1h expiry |
| **`bridge`** | `core.BridgePlugin` | Exposes `mintrun` capabilities to external AI agent harnesses | • **`mcp`** — Full Model Context Protocol (JSON-RPC 2.0 over `stdio`) server exposing `mintrun_exec`, `mintrun_plugins`, and the read-only governance tools `mintrun_policy_check` and `mintrun_audit` |

## Repository Layout

```text
mintrun/
├── cmd/mintrun/
│   ├── main.go                           # CLI entrypoint (exec, secret, plugin, mcp, audit, init, doctor, shim, apps, relay, watch), settings.json
│   ├── setup.go                          # Guided onboarding (mintrun init) and read-only diagnostics (mintrun doctor)
│   ├── shim.go                           # PATH shims (mintrun shim): block-and-redirect or transparent auto-wrap
│   ├── apps.go                           # Non-interactive MCP entries for Claude Code, Claude Desktop & Cursor (mintrun apps), JSON output
│   ├── relay.go                          # Team relay CLI subcommands (mintrun relay serve, device add|remove|list)
│   ├── watch.go                          # Built-in app.sock controller & token-guarded loopback dashboard (mintrun watch)
│   ├── main_test.go                      # End-to-end CLI & subcommand test suite
│   ├── setup_test.go                     # Hermetic init and doctor test suite
│   ├── shim_test.go                      # Hermetic CLI shim (block, auto, env-tightening, shell profiles, doctor) test suite
│   ├── apps_test.go                      # Hermetic mintrun apps test suite (stub claude, byte-exact config edits)
│   └── examples_test.go                  # Installs and runs the example plugins against stand-ins
├── internal/
│   ├── core/
│   │   ├── plugin.go                     # Plugin ABI, Registry, SHA-256 pinning & ExternalPlugin SDK
│   │   ├── runner.go                     # ExecBlind lifecycle, Policy Engine, 5-Encoding Scrubber, Output Cap, TailAudit
│   │   ├── procgroup_*.go                # Process-group kill on timeout/cancel (Unix; no-op elsewhere)
│   │   ├── sandbox_*.go                  # Linux user+mount namespace + seccomp-bpf sandbox helper (no-op elsewhere)
│   │   ├── core_test.go                  # Core JIT mint, scrub, revoke, policy & MCP test suite
│   │   ├── sandbox_linux_test.go         # Linux namespace, tmpfs, capability-drop & seccomp-bpf test suite
│   │   └── sandbox_integration_test.go   # Real macOS sandbox-exec and Linux namespace/libsecret checks (`-tags integration` only)
│   └── builtin/
│       ├── keychain.go                   # macOS Keychain / Linux libsecret + AES-256-GCM fallback & 1Password vault
│       ├── cloudflare.go                 # Built-in Cloudflare, GitHub (RS256 JWT), AWS STS (SigV4) & GCP (JWT bearer) providers
│       ├── mcp.go                        # MCP JSON-RPC 2.0 stdio bridge server
│       ├── telegram.go                   # Telegram approval channel (Bot API long polling)
│       ├── slack.go                      # Slack approval channel (polls a DM's reactions)
│       ├── appbroker.go                  # mintrun macOS app channel over ~/.mintrun/app.sock (approval & stop)
│       ├── relay.go                      # TLS 1.3 SPKI-pinned team relay server & client, per-device rate limit & lease cap
│       ├── watch.go                      # Built-in app.sock v1 server & token-guarded loopback dashboard
│       ├── builtin_test.go               # Comprehensive provider, vault, and MCP unit test suite
│       ├── telegram_test.go              # Telegram approval against a local Bot API
│       ├── slack_test.go                 # Slack approval against a local Web API
│       ├── appbroker_test.go             # App approval and tracking against a local socket
│       ├── relay_test.go                 # Team relay TLS 1.3 SPKI pin, device auth, rate-limit, lease-cap & e2e tests
│       ├── watch_test.go                 # WatchServer app.sock, loopback Host & dashboard token guard tests
│       └── keychain_integration_test.go  # Real macOS Keychain round trip (`-tags integration` only)
├── macos/                                # Native macOS Swift NSStatusBar Menu Bar companion for ~/.mintrun/app.sock
│   ├── MintrunMenuBar.swift              # Single-file AppKit menu bar controller (approvals, active leases, pause, AI apps)
│   ├── build.sh                          # Compiles macos/MintrunMenuBar with swiftc
│   └── README.md                         # Build and usage instructions for the macOS Menu Bar companion
├── examples/plugins/                     # Plugins built into the binary (`plugin install <name>`): bitwarden (vault), vercel & postgres-jit (providers)
├── scripts/
│   ├── release.sh                        # Release archives for macOS and Linux (arm64, amd64) with SHA256SUMS; signs and notarizes the macOS binaries when configured
│   └── verify.sh                         # Every acceptance check: gofmt, go vet, tests with a coverage gate above 90%, build & smoke test
└── docs/
    ├── assets/                           # SVG architectural diagrams
    ├── architecture.md                   # This page: plugin kinds and repository layout
    ├── providers.md                      # Cloudflare, GitHub, AWS, and Google Cloud setup, and static mode
    ├── approvals.md                      # The mintrun app, `mintrun watch`, the macOS dialog, Telegram, and Slack
    ├── security-model.md                 # Policy, scrubber, vault limits, sandbox, no_network, team relay, semantic screen
    ├── plugins.md                        # The plugin protocol and plugin management
    ├── roadmap.md                        # Milestones v0.1.0 to v0.14.0
    ├── threat-model.md                   # What mintrun promises, the tests behind each promise, and its limits
    └── video/                            # Self-contained HTML/MP4 motion overview & storyboard
```
