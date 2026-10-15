# `checks.md` — Verification Evidence

> Executed against the current source tree (`100%` Go standard library, `0` external dependencies). All metrics come from observed command execution.
>
> `go test ./...` runs hermetically offline using mock `security`/`secret-tool` scripts, `httptest` servers, and temporary `MINTRUN_HOME` directories. It never calls live cloud APIs, mutates `~/.mintrun`, or touches the real macOS Keychain. The real macOS Keychain round-trip test is gated behind `-tags integration`.

---

## 1. Standard Verification Pipeline

| # | Requirement | Verdict | Evidence |
| :---: | :--- | :---: | :--- |
| 1 | `gofmt -s -l cmd internal` & `go vet ./...` | `pass` | `gofmt` reports 0 unformatted files; `go vet ./...` exits 0 |
| 2 | `go test -count=1 ./...` | `pass` | `cmd/mintrun`, `internal/builtin`, and `internal/core` all pass |
| 3 | Total statement coverage `> 90%` (without build tags) | `pass` | `go tool cover -func=coverage.out` reports **92.7%** total (`cmd/mintrun` 86.9%, `internal/builtin` 93.6%, `internal/core` 93.5%); `coverage.out` removed |
| 4 | `go test -race -count=1 ./...` | `pass` | All 3 packages pass with the race detector enabled (0 data races) |
| 5 | `go build -trimpath -o mintrun ./cmd/mintrun` | `pass` | Exits 0; `strings mintrun \| grep -cF "$HOME"` returns `0` |
| 6 | `./mintrun plugin list` | `pass` | Lists all 7 built-in plugins: `mcp 0.1.0`, `aws 0.4.0`, `cloudflare 0.1.0`, `gcp 0.5.0`, `github 0.2.0`, `1password 0.2.0`, `keychain 0.5.0` |
| 7 | Cross-compilation (`GOOS=linux`, `GOOS=windows`, `GOOS=freebsd`) | `pass` | `go build ./...` exits 0 across all target platforms |
| 8 | Live macOS Keychain integration (`-tags integration`) | `pass` | `go test -tags integration -count=1 -v -run TestKeychainVaultRealKeychain ./internal/builtin` passes (`0.32s`), round-tripping multi-line UTF-8 secrets via `security -i` / `-g` and cleaning up the test item (exit 44 after deletion) |
| 9 | Zero external dependencies (Rule 1) | `pass` | `go list -m all` lists only the module path; `go.mod` contains 0 `require` directives |
| 10 | No `.github/` directory (Rule 2) | `pass` | `.github/` does not exist in the working tree or commit history |
| 11 | Zero-Secret & Zero-PII scan (Rule 3) | `pass` | Automated scan across all tracked files and commit history for home directory paths, usernames, hostnames, emails, device UUIDs, PEM keys, and live token patterns returns 0 hits (verified against a 24/24 positive-control fixture) |

---

## 2. Security & Capability Verification Matrix

| Area | Requirement | Verdict | Test / Verification Evidence |
| :--- | :--- | :---: | :--- |
| **Scrubber & Lease Handles** | Scrub all `ExecBlind` exit paths (including `provider.Mint` failures), use opaque `Lease.ID` handles (`gh-inst-<id>-<unix>`), and keep revocation tokens in `Lease.RevokeSecret` (`json:"-"`) | `pass` | `TestExecBlindAndScrubber`, `TestGitHubProviderAndJWTSigningComprehensive` |
| **Fail-Closed Policy Gate** | Deny empty scopes/permissions when allowlists are set, fail closed on malformed `policy.json`, match `blocked_commands` case-insensitively, and share `CheckPolicy` between `ExecBlind` and MCP `mintrun_policy_check` | `pass` | `TestPolicyFailClosedPhase45PRB`, `TestCheckPolicyMatchesExecBlind` |
| **Explicit Static Mode** | `cloudflare`, `github`, `aws`, and `gcp` enter static mode only when `mode=static` or the `static` permission is explicitly requested and permitted by `allow_static: true`; signing keys (GitHub App PEM, GCP SA JSON/PEM) are refused in static mode | `pass` | `TestPolicyFailClosedPhase45PRB`, `TestGitHubProviderAndJWTSigningComprehensive`, `TestAWSProviderComprehensive`, `TestGCPProviderPhase5` |
| **GitHub Master Parsing** | `GitHubProvider.Mint` parses composite (`<app_id>:<installation_id>:<pem>`), `<id>:<jwt>`, and bare JWT secrets identically when `params.installation_id` is set, refuses any bearer containing `-----BEGIN`, and scrubs bearer tokens from API error bodies | `pass` | `TestGitHubProviderAndJWTSigningComprehensive` (12 subtests) |
| **Plugin & Vault Isolation** | Reject path-traversal plugin names (`safePluginName`), block external plugins from shadowing built-ins, require `https://` + `#sha256=` for remote installs, and require `MINTRUN_VAULT_KEY` with salted PBKDF2-HMAC-SHA256 + atomic writes for `vault.json` | `pass` | `TestPluginRegistryAndExternalSDK`, `TestFileVaultPassphraseRequiredPhase45PRC` |
| **Child Env Isolation** | `-clean-env`, MCP `clean_env`, and policy `clean_env` / `allowed_env` globs restrict child environment variables and never pass `MINTRUN_VAULT_KEY` | `pass` | `TestExecBlindCleanEnv`, `TestMCPBridgeExecCleanEnv` |
| **GCP & Linux Vault** | `gcp` provider signs RS256 JWT assertions, exchanges them for scoped OAuth2 tokens, scrubs derived secrets from error responses, and sends revocation tokens in the POST body; Linux `secret-tool` vault passes secrets over `stdin` | `pass` | `TestGCPProviderPhase5`, `TestKeychainVaultLinuxSecretTool` |
| **MCP Governance** | `mintrun_policy_check` dry-runs `CheckPolicy` without touching vaults or spawning processes; `mintrun_audit` redacts command arguments to `[argv0, "[MINTRUN:REDACTED]"]` | `pass` | `TestMCPBridgeGovernanceTools`, `TestMCPBridgeComprehensive` |
| **Keychain Stdin & Warnings** | macOS Keychain stores via `security -i` on `stdin` (refusing lines `> 4095` bytes), reads via `-g`, treats exit 44 as a quiet miss, and warns on `stderr` before falling back to the file vault; CLI warns on `argv` secrets | `pass` | `TestKeychainVaultMacOSSecurity`, `TestKeychainVaultRealKeychain`, `TestCLISecretArgvWarning` |
| **Output Cap & Process Group** | Child `stdout`/`stderr` streams are capped at 4 MiB with straddle-safe secret prefix trimming and `[MINTRUN:TRUNCATED n bytes]`; timeout or `SIGINT`/`SIGTERM`/`SIGHUP` kills the child process group on Unix | `pass` | `TestExecBlindOutputCap`, `TestExecBlindKillsProcessGroup` |
| **AWS SigV4 & Lease Reporting** | `signAWSSigV4` signs `x-amz-security-token` when present (verified against AWS's `post-sts-header-before` test vector); `AWSProvider.Revoke` returns an error for STS leases so `revoked: false` is reported | `pass` | `TestAWSSigV4FixedVector`, `TestAWSProviderComprehensive` |
| **Hermetic Default Test Suite** | `go test ./...` invokes zero system credential or UI binaries (`security`, `osascript`, `op`, `stty`) | `pass` | Verified with logging binary stubs (0 calls without tags; 4 `security` calls with `-tags integration`) |

---

## 3. Known Limitations & Open Items

| Item | Status | Notes |
| :--- | :---: | :--- |
| Live AWS STS and Google OAuth2 API calls | `unresolved` | Intentionally mocked via `httptest` and pinned to published test vectors; never called with live credentials in automated tests |
| Live `secret-tool` execution on a Linux host | `unresolved` | Verified via mock scripts on macOS; the Linux branch of `NewKeychainVault` requires a Linux host with `libsecret` |
| Interactive `setEcho` terminal test | `unresolved` | `setEcho` (`cmd/mintrun/main.go`) requires a real TTY and is 0% covered in headless unit tests |
| macOS Keychain ~2 KB secret ceiling | `by design` | `security -i` splits lines over 4095 bytes; secrets larger than ~2 KB (such as GCP service-account JSON keys) fall back to the encrypted file vault with a warning and require `MINTRUN_VAULT_KEY` |
| Same-user child process access | `by design` | Documented in [README.md](README.md): `mintrun` keeps raw secrets out of agent context and transcripts, but does not OS-sandbox same-user child processes |
| OS network sandbox (`no_network: true`) | `deferred` | Design documented in [README.md](README.md) and [plan.md](plan.md) |
| Policy binding for `params.installation_id` | `deferred` | MCP callers can supply `params.installation_id` to override the GitHub App installation ID; binding it in `CheckPolicy` is tracked in [plan.md](plan.md) |
| `1password` CLI (`op item create`) `argv` | `deferred` | `OnePasswordVault.SetSecret` still passes `credential=<secret>` on `argv`; migrating to `stdin` JSON template requires verification against `op` |
| Linux HITL approval dialog | `deferred` | `-approve` / `require_approval` uses `osascript` on macOS and fails closed on Linux |
| Tail-reading `~/.mintrun/audit.jsonl` | `deferred` | `mintrun audit` and `mintrun_audit` currently read the full JSONL file |
