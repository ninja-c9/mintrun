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
| **`v0.8.0` — Secrets Off argv, Bounded Audit Reads & Long Keychain Secrets** | ✅ Done | 1Password `secret set` pipes the secret to `op item create` on `stdin` and archives older items with the same title; `mintrun audit` and MCP `mintrun_audit` stream `audit.jsonl` through `core.TailAudit`, so memory no longer grows with the log; macOS Keychain secrets too long for one `security -i` line are stored as up to 16 checksummed parts (24,000 bytes); the hidden `secret set` prompt is tested with a stub `stty`; `93.6%` verified statement coverage |
| **`v0.8.1` — Keystore Fallback Cleanup** | ⏳ Untagged | A `secret set` that falls back to the file vault after a failed Keychain or libsecret store removes the older keystore item for the key, which used to shadow the new secret on read, or fails with an error saying that item still wins; `93.7%` verified statement coverage |

---

## 2. Current Repository Status

- **Plan & Backlog:** [plan.md](plan.md)
- **Verification Report:** [checks.md](checks.md)
- **Security Audit Report:** [audit.md](audit.md)
- **Pipeline Status:**
  - `gofmt -s -l cmd internal` and `go vet ./...`: clean (`0` issues)
  - `go test -count=1 -cover ./...` (without build tags): **93.7%** total statement coverage (`cmd/mintrun` 95.1%, `internal/builtin` 93.3%, `internal/core` 93.8%)
  - `go test -race -count=1 ./...`: pass (`0` data races)
  - `go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list`: pass (`7` built-in plugins registered, `0` local path strings in binary)
  - Cross-compilation (`GOOS=linux`, `GOOS=windows`, `GOOS=freebsd`): pass

---

## 3. Open Items & Next Steps

- **`v0.8.1` Tag:** Workstream F is untagged; tag it once approved.
- **Stale File-Vault Copy (bug):** A keystore store that succeeds leaves any older file-vault copy of the key, which `GetSecret` returns when a later keystore lookup fails ([plan.md](plan.md) backlog item 1).
- **OS Network Sandbox (`no_network: true`):** Optional fail-closed network namespace / `sandbox-exec` isolation for child processes; awaiting approval of the open questions in [plan.md](plan.md).
- **Live 1Password Verification:** Run `mintrun secret set`, `check`, and `rm` against a real 1Password account; the `stdin` item template and the archiving of older items are tested against a mock `op` only.
- **Linux Host Verification:** Verify `secret-tool` and HITL behavior on a Linux host.
- **Audit Read Time:** `TailAudit` bounds memory but still scans the whole log on every read; seek back from the end if it reaches gigabytes.
