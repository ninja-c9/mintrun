# `mintrun` Project Progress & Status

## 1. Release Milestones

| Release | Status | Key Deliverables & Verification Summary |
| :--- | :---: | :--- |
| **`v0.1.0` — Core Runtime & Enclave ABI** | ✅ Done | Core `VaultPlugin` / `ProviderPlugin` / `BridgePlugin` ABI, macOS Keychain vault, Cloudflare JIT sub-token provider, MCP `stdio` bridge, stream scrubber, policy engine, and JSONL audit logger |
| **`v0.2.0` — Multi-Cloud JIT Providers & Vaults** | ✅ Done | Built-in GitHub App RS256 JWT + Installation Token minter (`github`) and 1Password CLI biometric vault (`1password`) |
| **`v0.3.0` — Enclave Hardening & HITL Approval** | ✅ Done | Multi-encoding scrubber (Raw, Base64, RawBase64, Hex, URL), macOS `osascript` HITL confirmation gate (`-approve`), and SHA-256 remote plugin digest pinning |
| **`v0.4.0` — AWS STS, AES-256-GCM Vault & Governance** | ✅ Done | Built-in AWS STS SigV4 `AssumeRole` minter (`aws`), AES-256-GCM encrypted `~/.mintrun/vault.json`, wildcard policy globs, and audit log filtering |
| **`v0.5.0` — Security Remediation, Env Isolation, GCP, Linux Vault & MCP Governance** | ✅ Done | Full exit-path scrubbing and opaque lease IDs; fail-closed policy evaluation and `allow_static` gate; plugin path/shadowing isolation and salted PBKDF2-HMAC-SHA256 file vault (`MINTRUN_VAULT_KEY`); child `clean_env` / `allowed_env` isolation; built-in `gcp` OAuth2 JWT provider; Linux `secret-tool` vault; MCP `mintrun_policy_check` and `mintrun_audit` governance tools |
| **`v0.6.0` — Operational Hardening** | ✅ Done | macOS Keychain secrets over `security -i` `stdin`, loud keystore fallback warnings, CLI `argv` secret warnings and echo-off prompt; 4 MiB child output cap with straddle-safe secret scrubbing and Unix process-group kill on timeout or `SIGINT`/`SIGTERM`/`SIGHUP`; SigV4 `x-amz-security-token` signing and expires-only AWS STS lease reporting (`revoked: false`); explicit static mode required for `github` and `aws`; hermetic default `go test ./...` (`-tags integration` for real Keychain); `92.6%` verified statement coverage |
| **`v0.7.0` — GitHub Installation Binding** | ✅ Done | Consistent GitHub master secret parsing with `params.installation_id`; `github` refuses a `params.installation_id` that differs from the installation pinned in the stored credential; policy `allowed_installations` (exact, fail-closed, enforced in `CheckPolicy` for both `ExecBlind` and `mintrun_policy_check`); `params` in the MCP input schema; `92.7%` verified statement coverage |

---

## 2. Current Repository Status

- **Plan & Backlog:** [plan.md](plan.md)
- **Verification Report:** [checks.md](checks.md)
- **Security Audit Report:** [audit.md](audit.md)
- **Pipeline Status:**
  - `gofmt -s -l cmd internal` and `go vet ./...`: clean (`0` issues)
  - `go test -count=1 -cover ./...` (without build tags): **92.7%** total statement coverage (`cmd/mintrun` 86.9%, `internal/builtin` 93.7%, `internal/core` 93.5%)
  - `go test -race -count=1 ./...`: pass (`0` data races)
  - `go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list`: pass (`7` built-in plugins registered, `0` local path strings in binary)
  - Cross-compilation (`GOOS=linux`, `GOOS=windows`, `GOOS=freebsd`): pass

---

## 3. Open Items & Next Steps

- **OS Network Sandbox (`no_network: true`):** Optional fail-closed network namespace / `sandbox-exec` isolation for child processes.
- **1Password CLI (`op item create`) `stdin` Secret Passing:** Move secret creation off `argv` onto `stdin`.
- **Linux Host Verification & TTY Coverage:** Verify `secret-tool` and HITL behavior on a Linux host, and add PTY test coverage for `setEcho`.
- **Audit Log Tail-Reading:** Read `~/.mintrun/audit.jsonl` from the tail for bounded memory usage on large logs.
