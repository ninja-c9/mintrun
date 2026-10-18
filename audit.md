# `mintrun` Security Audit Report

> **Scope:** Full source tree (`cmd/mintrun`, `internal/core`, `internal/builtin`) — 100% Go standard library.
> **Methodology:** Manual line-by-line review of source and tests against the project invariants in [AGENTS.md](AGENTS.md), verified with real pipeline execution.

---

## 1. Executive Summary

`mintrun` provides a zero-dependency Go runtime with a clean Plugin ABI, `ExecBlind` lifecycle, and MCP `stdio` bridge.

An initial comprehensive security review identified 24 findings across the runtime, providers, vaults, and plugin installer. Because `mintrun`'s core value proposition is a **zero-knowledge credential enclave** and **blind CLI runner**, findings that allowed secrets to leak into audit logs, MCP responses, process arguments, or child environments were prioritized and remediated.

| Severity | Count | Summary | Resolution Status |
| :--- | :---: | :--- | :---: |
| **Critical** | 3 | Live GitHub installation token leaked as `lease_id`; path traversal in plugin install; file-vault key derived from filesystem path | ✅ Fixed |
| **High** | 5 | Fail-open policy evaluation (empty scope/permissions, malformed `policy.json`, implicit/ungated `static` mode); unscrubbed mint errors; external plugin shadowing built-ins | ✅ Fixed |
| **Medium** | 8 | Ambient host environment inheritance; secrets on helper CLI `argv`; silent keystore fallback; misleading `revoked: true` on non-revocable leases; HTTP remote plugin install; case-sensitive command filter; no network sandbox | ✅ Fixed |
| **Low** | 8 | Unbounded child output buffers; single-process kill on timeout; non-atomic vault writes; unchecked `rand.Read`; unsigned `X-Amz-Security-Token`; legacy plaintext vault map; `.github/` history; non-hermetic Keychain test | ✅ Fixed |

---

## 2. Critical Findings

### C1 — Path Traversal in Local `InstallPlugin`
- **Location:** `internal/core/plugin.go`
- **Issue:** Local plugin installation joined `manifest.Name` directly into `pluginsDir` before calling `os.RemoveAll(destDir)`. A manifest with `"name": "../../target"` could delete and overwrite arbitrary user directories.
- **Remediation:** Validate all plugin names on both install and remove via `safePluginName` (single path segment, rejecting `/`, `\`, `.`, and `..`).

### C2 — GitHub Installation Token Used as Public `lease_id`
- **Location:** `internal/builtin/cloudflare.go`, `internal/core/runner.go`
- **Issue:** `GitHubProvider.Mint` set `Lease.ID = resp.Token` so `Revoke` could read the token back. Because `ExecResult.LeaseID` is returned to MCP agents and written to `~/.mintrun/audit.jsonl`, the live GitHub installation token leaked directly into agent context and disk logs.
- **Remediation:** Separated public lease handles (`Lease.ID = gh-inst-<installation_id>-<unix>`) from revocation credentials (`Lease.RevokeSecret` with `json:"-"`, never serialized), and added `lease.ID` and `Lease.RevokeSecret` to the `Scrub` redaction set.

### C3 — File-Vault Key Derived From Filesystem Path Without Passphrase
- **Location:** `internal/builtin/keychain.go`
- **Issue:** When `MINTRUN_VAULT_KEY` was unset, the AES-256-GCM key was derived solely from a static string and `k.HomeDir` via a single SHA-256 hash without a salt or KDF. In addition, `MINTRUN_VAULT_KEY` was inherited by child processes when set.
- **Remediation:** Require a non-empty `MINTRUN_VAULT_KEY` passphrase for the file vault, derive the key with `crypto/pbkdf2.Key(sha256.New, ...)` (210,000 iterations) and a per-vault random salt persisted in `vault.json` (`__salt__`), strip `MINTRUN_VAULT_KEY` from all child environments, and document the exact same-user threat model in [README.md](README.md).

---

## 3. High Findings

### H1 — Policy Evaluation Skipped When Scope or Permissions Were Empty
- **Location:** `internal/core/runner.go`
- **Issue:** `allowed_scopes` and `allowed_permissions` checks were skipped when `req.Scope == ""` or `len(req.Permissions) == 0`. For Cloudflare, an empty scope minted a token across all account zones (`com.cloudflare.api.account.zone.*`).
- **Remediation:** Enforce strict allowlist semantics in `CheckPolicy`: when `allowed_scopes` or `allowed_permissions` is non-empty, an empty request value is denied unless `*` is explicitly allowed.

### H2 — Ungated Static Mode Bypassed `allowed_permissions`
- **Location:** `internal/core/runner.go`, `internal/builtin/cloudflare.go`
- **Issue:** Requesting `permissions: ["static"]` or `params: {"mode": "static"}`—or triggering implicit static fallbacks in `github` (PAT without installation ID) and `aws` (non-ARN scope)—injected the raw master secret into the child process without policy authorization.
- **Remediation:** Added `allow_static` (default `false`) to `PolicyRule` in `CheckPolicy`, required explicit `static` requests across all four built-in providers (`cloudflare`, `github`, `aws`, `gcp`), and refused long-lived signing keys (GitHub App PEM, GCP service-account JSON/PEM) in static mode.

### H3 — Malformed `policy.json` Ignored (Fail-Open)
- **Location:** `internal/core/runner.go`
- **Issue:** JSON unmarshaling errors when loading `~/.mintrun/policy.json` were discarded, causing syntax errors to silently disable all policy rules.
- **Remediation:** Surface parse errors, warn on `stderr`, and deny execution (fail-closed) whenever `policy.json` exists but cannot be parsed.

### H4 — Unscrubbed Mint and Pre-Exec Error Paths
- **Location:** `internal/core/runner.go`, `internal/builtin/cloudflare.go`
- **Issue:** When `provider.Mint` failed, the raw error text (which can include plugin `stderr` or upstream HTTP error bodies echoing credentials) was written to `audit.jsonl` and returned to callers unscrubbed.
- **Remediation:** Pass all `ExecBlind` error paths, `LeaseID`, and audit fields through `Scrub()` with the master secret and all lease secrets, and scrub provider-derived bearer assertions inside `GCPProvider` and `GitHubProvider`.

### H5 — External Plugins Could Shadow Built-in Plugins
- **Location:** `internal/core/plugin.go`
- **Issue:** `Registry.Register` overwrote existing plugins of the same name, allowing an external plugin in `~/.mintrun/plugins/` to impersonate a built-in vault or provider and intercept master secrets.
- **Remediation:** Reject any non-builtin plugin registration whose name collides with a registered built-in vault, provider, or bridge.

---

## 4. Medium & Low Findings

| ID | Severity | Location | Finding | Resolution |
| :--- | :---: | :--- | :--- | :--- |
| **M1** | Medium | `internal/core/runner.go` | Child process inherited full `os.Environ()` | Added `-clean-env` / MCP `clean_env` and policy `clean_env` / `allowed_env` globs; `MINTRUN_VAULT_KEY` is never inherited |
| **M2** | Medium | `internal/core/runner.go` | Child process retains network access and can exfiltrate lease tokens via script interpreters | Fixed in `v0.12.0` (opt-in): `no_network` (policy `"no_network": true`, CLI `-no-network`, MCP `no_network`) runs the child in the OS sandbox with egress blocked: `sandbox-exec` `(deny network*)` on macOS, `CLONE_NEWNET` plus a `seccomp-bpf` filter on `socket`, `connect`, and `bind` on Linux `amd64`/`arm64`; without it the network stays open, as [README.md](README.md) says (rule 46) |
| **M3** | Medium | `internal/builtin/cloudflare.go` | `AWSProvider.Revoke` returned `nil`, reporting `revoked: true` for STS tokens that cannot be revoked early | `AWSProvider.Revoke` returns an error for ephemeral STS leases so `revoked: false` is reported; duration clamped to 900–43200s |
| **M4** | Medium | `internal/core/runner.go` | Denylist command filter alone cannot stop shell or interpreter env dumps | Combined case-insensitive command filtering with `clean_env` / `allowed_env` environment isolation |
| **M5** | Medium | `internal/builtin/keychain.go`, `cmd/mintrun/main.go` | Secrets passed on `argv` (`security -w`, `secret set <provider> <secret>`) were visible in `ps` and shell history | macOS Keychain writes via `security -i` on `stdin`; Linux uses `secret-tool` on `stdin`; CLI disables echo via `stty` and warns when a secret is passed on `argv` (`op item create` argv deferred) |
| **M6** | Medium | `internal/core/plugin.go` | Remote plugin install allowed plaintext HTTP, had no client timeout, and trusted self-declared bundle digests | Require `https://` (or loopback), enforce an out-of-band `#sha256=<hex>` URL fragment, and set an HTTP client timeout |
| **M7** | Medium | `internal/builtin/keychain.go` | Keystore failures silently fell back to the file vault | Distinguish missing items (`errSecItemNotFound` exit 44 / empty `secret-tool` miss) from errors; warn on `stderr` before falling back |
| **M8** | Medium | `internal/core/runner.go` | `blocked_commands` matching was case-sensitive | Match `blocked_commands` case-insensitively |
| **L1** | Low | `internal/core/runner.go` | Unbounded `stdout`/`stderr` buffers allowed memory exhaustion | Cap each stream at `MaxOutputBytes` (4 MiB) with straddle-safe secret prefix trimming and `[MINTRUN:TRUNCATED n bytes]` |
| **L2** | Low | `internal/core/runner.go`, `internal/core/procgroup_*.go` | Timeout killed only the direct child process, leaving grandchildren holding pipes and leases | Run Unix children in a dedicated process group (`Setpgid`), `SIGKILL` the group on timeout/cancel, bound pipe wait with `WaitDelay` (5s), and handle `SIGINT`/`SIGTERM`/`SIGHUP` |
| **L3** | Low | `internal/builtin/keychain.go` | Non-atomic writes to `vault.json` | Write to a temporary file, `Sync()`, and `os.Rename()` atomically |
| **L4** | Low | `internal/builtin/keychain.go` | Unchecked `crypto/rand.Read` when generating nonces | Check `rand.Read` errors for both salt and GCM nonce generation |
| **L5** | Low | `internal/builtin/cloudflare.go` | `signAWSSigV4` sent `X-Amz-Security-Token` without including it in `SignedHeaders` | Sign all present headers (`content-type`, `host`, `x-amz-date`, `x-amz-security-token`) in sorted order; verified against the official AWS SigV4 test vector |
| **L6** | Low | `internal/builtin/keychain.go` | `readMap` accepted legacy unencrypted plaintext JSON maps | Fail closed if `vault.json` lacks either `__aes256gcm__` or `__salt__` |
| **L7** | Low | `go.mod`, git history | Historical commit introduced `.github/workflows/ci.yml` prior to removal | Removed `.github/workflows/ci.yml` from repository history |
| **L8** | Low | `internal/builtin/builtin_test.go` | Default `go test ./...` touched the live macOS Keychain | Moved live Keychain test to `keychain_integration_test.go` behind `//go:build integration` |
