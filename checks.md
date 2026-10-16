# `checks.md` — Verification Evidence

> Executed against the current source tree (`100%` Go standard library, `0` external dependencies). All metrics come from observed command execution.
>
> `go test ./...` runs hermetically offline using mock `security`/`secret-tool`/`op`/`stty` scripts, `httptest` servers, and temporary `MINTRUN_HOME` directories. It never calls live cloud APIs, mutates `~/.mintrun`, or touches the real macOS Keychain. The real macOS Keychain round-trip test is gated behind `-tags integration`.

---

## 1. Standard Verification Pipeline

| # | Requirement | Verdict | Evidence |
| :---: | :--- | :---: | :--- |
| 1 | `gofmt -s -l cmd internal` & `go vet ./...` | `pass` | `gofmt` reports 0 unformatted files; `go vet ./...` exits 0 |
| 2 | `go test -count=1 ./...` | `pass` | `cmd/mintrun`, `internal/builtin`, and `internal/core` all pass |
| 3 | Total statement coverage `> 90%` (without build tags) | `pass` | `go tool cover -func=coverage.out` reports **93.6%** total (`cmd/mintrun` 95.1%, `internal/builtin` 93.1%, `internal/core` 93.8%); `coverage.out` removed |
| 4 | `go test -race -count=1 ./...` | `pass` | All 3 packages pass with the race detector enabled (0 data races) |
| 5 | `go build -trimpath -o mintrun ./cmd/mintrun` | `pass` | Exits 0; `strings mintrun \| grep -cF "$HOME"` returns `0` |
| 6 | `./mintrun plugin list` | `pass` | Lists all 7 built-in plugins: `mcp 0.1.0`, `aws 0.4.0`, `cloudflare 0.1.0`, `gcp 0.5.0`, `github 0.2.0`, `1password 0.2.0`, `keychain 0.5.0` |
| 7 | Cross-compilation (`GOOS=linux`, `GOOS=windows`, `GOOS=freebsd`) | `pass` | `go build ./...` exits 0 across all target platforms |
| 8 | Live macOS Keychain integration (`-tags integration`) | `pass` | `go test -tags integration -count=1 -v -run TestKeychainVaultRealKeychain ./internal/builtin` passes (`0.86s`), round-tripping multi-line UTF-8 secrets via `security -i` / `-g`, then a 3,005-byte secret stored as 3 parts and a 2,501-byte one as 2 parts under a new generation; after deletion the item and every part read as a miss (exit 44), and `security dump-keychain` lists 0 test items |
| 9 | Zero external dependencies (Rule 1) | `pass` | `go list -m all` lists only the module path; `go.mod` contains 0 `require` directives |
| 10 | No `.github/` directory (Rule 2) | `pass` | `.github/` does not exist in the working tree or commit history |
| 11 | Zero-Secret & Zero-PII scan (Rule 3) | `pass` | Automated scan across all tracked files and commit history for home directory paths, usernames, hostnames, emails, device UUIDs, PEM keys, and live token patterns returns 0 hits (verified against a 24/24 positive-control fixture); the installation-binding change (added diff lines and commit messages) re-scanned with 23 patterns: 0 hits, planted control 23/23; Workstream E (added diff lines and commit messages) re-scanned with 24 patterns: 0 hits, planted control 24/24 |

---

## 2. Security & Capability Verification Matrix

| Area | Requirement | Verdict | Test / Verification Evidence |
| :--- | :--- | :---: | :--- |
| **Scrubber & Lease Handles** | Scrub all `ExecBlind` exit paths (including `provider.Mint` failures), use opaque `Lease.ID` handles (`gh-inst-<id>-<unix>`), and keep revocation tokens in `Lease.RevokeSecret` (`json:"-"`) | `pass` | `TestExecBlindAndScrubber`, `TestGitHubProviderAndJWTSigningComprehensive` |
| **Fail-Closed Policy Gate** | Deny empty scopes/permissions when allowlists are set, fail closed on malformed `policy.json`, match `blocked_commands` case-insensitively, and share `CheckPolicy` between `ExecBlind` and MCP `mintrun_policy_check` | `pass` | `TestPolicyFailClosedPhase45PRB`, `TestCheckPolicyMatchesExecBlind` |
| **Explicit Static Mode** | `cloudflare`, `github`, `aws`, and `gcp` enter static mode only when `mode=static` or the `static` permission is explicitly requested and permitted by `allow_static: true`; signing keys (GitHub App PEM, GCP SA JSON/PEM) are refused in static mode | `pass` | `TestPolicyFailClosedPhase45PRB`, `TestGitHubProviderAndJWTSigningComprehensive`, `TestAWSProviderComprehensive`, `TestGCPProviderPhase5` |
| **GitHub Master Parsing** | `GitHubProvider.Mint` parses composite (`<app_id>:<installation_id>:<pem>`), `<id>:<jwt>`, and bare JWT secrets identically when `params.installation_id` is set, refuses a param that differs from the pinned installation before any request, refuses any bearer containing `-----BEGIN`, and scrubs bearer tokens from API error bodies | `pass` | `TestGitHubProviderAndJWTSigningComprehensive` (16 subtests) |
| **Installation Binding** | Policy `allowed_installations` is an exact, fail-closed allowlist for `params.installation_id` in `CheckPolicy`, shared by `ExecBlind` and `mintrun_policy_check` (missing, unlisted, and path-like IDs are denied); the provider's pin check sends no request on a mismatch | `pass` | `TestCheckPolicyMatchesExecBlind`, `TestGitHubProviderAndJWTSigningComprehensive`; removing either check fails its test (mutation-checked on a copy) |
| **Plugin & Vault Isolation** | Reject path-traversal plugin names (`safePluginName`), block external plugins from shadowing built-ins, require `https://` + `#sha256=` for remote installs, and require `MINTRUN_VAULT_KEY` with salted PBKDF2-HMAC-SHA256 + atomic writes for `vault.json` | `pass` | `TestPluginRegistryAndExternalSDK`, `TestFileVaultPassphraseRequiredPhase45PRC` |
| **Child Env Isolation** | `-clean-env`, MCP `clean_env`, and policy `clean_env` / `allowed_env` globs restrict child environment variables and never pass `MINTRUN_VAULT_KEY` | `pass` | `TestExecBlindCleanEnv`, `TestMCPBridgeExecCleanEnv` |
| **GCP & Linux Vault** | `gcp` provider signs RS256 JWT assertions, exchanges them for scoped OAuth2 tokens, scrubs derived secrets from error responses, and sends revocation tokens in the POST body; Linux `secret-tool` vault passes secrets over `stdin` | `pass` | `TestGCPProviderPhase5`, `TestKeychainVaultLinuxSecretTool` |
| **MCP Governance** | `mintrun_policy_check` dry-runs `CheckPolicy` without touching vaults or spawning processes; `mintrun_audit` redacts command arguments to `[argv0, "[MINTRUN:REDACTED]"]` | `pass` | `TestMCPBridgeGovernanceTools`, `TestMCPBridgeComprehensive` |
| **Keychain Stdin & Warnings** | macOS Keychain stores via `security -i` on `stdin` (never sending a line `> 4095` bytes), reads via `-g`, treats exit 44 as a quiet miss, and warns on `stderr` before falling back to the file vault; CLI warns on `argv` secrets | `pass` | `TestKeychainVaultMacOSSecurity`, `TestKeychainVaultRealKeychain`, `TestCLISecretArgvWarning` |
| **Long Keychain Secrets** | A secret too long for one `security -i` line is stored as at most 16 parts of 1,500 bytes under a fresh random generation; the SHA-256 header item is written last and the previous generation's parts are removed after it; a read verifies the checksum, a missing or altered part is an error, and a secret over 24,000 bytes falls back to the file vault with a warning | `pass` | `TestKeychainVaultMacOSSecurity`, `TestKeychainVaultRealKeychain`; 9 mutants (old parts kept, no cleanup after a failed part, missing part made quiet, no checksum, header part count unchecked, delete leaves parts, header lookalike stored whole, header written first, no 24,000-byte cap) each fail a test |
| **1Password Secrets Off argv** | `OnePasswordVault.SetSecret` pipes a JSON item template to `op item create -` on `stdin`, archives older items with the same title (a failed archive only warns), and quotes only `op`'s `stderr`, with the secret scrubbed in raw and JSON-escaped form; an `op` found through a relative `PATH` entry is refused | `pass` | `TestKeychainAndOnePasswordVaults` (mock `op`); 3 mutants (no JSON-escaped scrub, the new item archived too, no `stdin` template) each fail the test. Live `op`: see §3 |
| **Bounded Audit Reads** | `core.TailAudit` streams `audit.jsonl` with a `bufio.Reader` (no line cap) and keeps only the last `limit` matches; `mintrun audit` copies the file as-is when unfiltered and filters through `TailAudit` otherwise; MCP `mintrun_audit` uses it with `limit` capped at 100 | `pass` | `TestTailAudit`, `TestMCPBridgeGovernanceTools`, `TestCLISubcommandsEndToEnd`; 5 mutants (case-sensitive provider, no window eviction, read error swallowed, newline kept, 64 KiB line cap) each fail a test |
| **Hidden Secret Prompt** | Interactive `secret set` runs `stty -echo` before reading; only when that succeeds does it run `stty echo` and print a newline after | `pass` | `TestCLISecretPromptHidesEcho` (stub `stty`, `/dev/null` as `stdin`; `setEcho` 100% covered); 4 mutants each fail the test |
| **Output Cap & Process Group** | Child `stdout`/`stderr` streams are capped at 4 MiB with straddle-safe secret prefix trimming and `[MINTRUN:TRUNCATED n bytes]`; timeout or `SIGINT`/`SIGTERM`/`SIGHUP` kills the child process group on Unix | `pass` | `TestExecBlindOutputCap`, `TestExecBlindKillsProcessGroup` |
| **AWS SigV4 & Lease Reporting** | `signAWSSigV4` signs `x-amz-security-token` when present (verified against AWS's `post-sts-header-before` test vector); `AWSProvider.Revoke` returns an error for STS leases so `revoked: false` is reported | `pass` | `TestAWSSigV4FixedVector`, `TestAWSProviderComprehensive` |
| **Hermetic Default Test Suite** | `go test ./...` invokes zero system credential or UI binaries (`security`, `osascript`, `op`, `stty`) | `pass` | Verified with logging binary stubs for `security`, `osascript`, `stty`, `op`, and `secret-tool` (0 calls without tags; 7 `security` calls with `-tags integration`) |

---

## 3. Known Limitations & Open Items

| Item | Status | Notes |
| :--- | :---: | :--- |
| Live AWS STS and Google OAuth2 API calls | `unresolved` | Intentionally mocked via `httptest` and pinned to published test vectors; never called with live credentials in automated tests |
| Live `secret-tool` execution on a Linux host | `unresolved` | Verified via mock scripts on macOS; the Linux branch of `NewKeychainVault` requires a Linux host with `libsecret` |
| Real-terminal echo test | `unresolved` | `TestCLISecretPromptHidesEcho` covers `setEcho` (100%) with a stub `stty` and `/dev/null` as `stdin`; no test drives a real terminal, since the Go standard library has no PTY |
| macOS Keychain 24,000-byte secret ceiling | `by design` | A secret too long for one `security -i` line is split into at most 16 parts of 1,500 bytes; a longer one falls back to the encrypted file vault with a warning and requires `MINTRUN_VAULT_KEY` |
| Same-user child process access | `by design` | Documented in [README.md](README.md): `mintrun` keeps raw secrets out of agent context and transcripts, but does not OS-sandbox same-user child processes |
| OS network sandbox (`no_network: true`) | `deferred` | Design documented in [README.md](README.md) and [plan.md](plan.md) |
| `params` from the CLI | `by design` | Only MCP agents send `params`, so a provider with `allowed_installations` (or a GitHub credential that pins no installation) works over MCP only |
| Live 1Password CLI (`op`) | `unresolved` | `OnePasswordVault` is tested against a mock `op` only: the `stdin` item template, the archiving of older items, and the scrubbed errors have not been run against a real 1Password account |
| Linux HITL approval dialog | `deferred` | `-approve` / `require_approval` uses `osascript` on macOS and fails closed on Linux |
| Audit read time | `by design` | `TailAudit` bounds memory by `limit`, but every read still scans the whole of `~/.mintrun/audit.jsonl`; seek back from the end if the log reaches gigabytes |
| Keystore fallback shadowing | `unresolved` | After a failed Keychain or libsecret store, the file vault holds the new secret but an older keystore item for the same key still wins on read; only a locked or failing keystore or a secret over 24,000 bytes reaches that path. Backlog item 1 in [plan.md](plan.md) |
