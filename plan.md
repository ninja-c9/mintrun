# `mintrun` Execution Plan & Backlog

> **Harness Spec:** [AGENTS.md](AGENTS.md) · **Latest Release:** `v0.9.0` · **Constraints:** 100% Go `1.24.0` standard library (`0` external dependencies), `> 90%` verified statement coverage measured without build tags.

---

## 1. Standard Acceptance Checks (`<layer_3_tools_hooks>`)

Every change to `cmd/` or `internal/` must pass the following verification pipeline before completion:

1. **Format & Static Analysis:**
   ```bash
   gofmt -s -l cmd internal && go vet ./...
   ```
2. **Hermetic Test Suite & Coverage Gate (`> 90%`):**
   ```bash
   go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -n 1 && rm -f coverage.out
   ```
3. **Race Detector & Cross-Platform Build:**
   ```bash
   go test -race -count=1 ./... && GOOS=linux go build ./... && GOOS=windows go build ./...
   ```
4. **Reproducible Binary Build & Smoke Test:**
   ```bash
   go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list
   ```
5. **Opt-In macOS Keychain Integration Check (macOS only):**
   ```bash
   go test -tags integration -count=1 -v -run TestKeychainVaultRealKeychain ./internal/builtin
   ```

---

## 2. Completed Workstreams

### Workstream A — Security Audit Remediation
- **Files:** `internal/core/runner.go`, `internal/core/plugin.go`, `internal/builtin/cloudflare.go`, `internal/builtin/keychain.go`
- **Deliverables:**
  1. Scrub all `ExecBlind` exit paths (including `provider.Mint` errors), `LeaseID`, and audit fields; separate public `Lease.ID` handles from `Lease.RevokeSecret` (`json:"-"`).
  2. Enforce fail-closed policy evaluation in `CheckPolicy`: deny empty scope/permissions when allowlists exist, fail closed on malformed `policy.json`, match `blocked_commands` case-insensitively, and gate static mode behind `allow_static: true`.
  3. Harden plugin isolation (`safePluginName` single-segment validation, block built-in shadowing, require `https://` and `#sha256=` for remote installs) and require a `MINTRUN_VAULT_KEY` passphrase with salted PBKDF2-HMAC-SHA256 and atomic writes for `vault.json`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestExecBlindAndScrubber|TestPolicyFailClosedPhase45PRB|TestPluginRegistryAndExternalSDK|TestFileVaultPassphraseRequiredPhase45PRC' ./internal/core ./internal/builtin
  ```

### Workstream B — Environment Isolation, GCP Provider, Linux Vault & MCP Governance
- **Files:** `internal/core/runner.go`, `internal/builtin/cloudflare.go`, `internal/builtin/keychain.go`, `internal/builtin/mcp.go`, `cmd/mintrun/main.go`
- **Deliverables:**
  1. Add `-clean-env`, MCP `clean_env`, and policy `clean_env` / `allowed_env` globs; never pass `MINTRUN_VAULT_KEY` to child processes.
  2. Add built-in `gcp` provider (100% stdlib RS256 JWT bearer assertion exchanged for scoped OAuth2 access tokens, derived-secret error scrubbing, and POST-body revocation) and Linux `secret-tool` vault support over `stdin`.
  3. Expose read-only MCP governance tools `mintrun_policy_check` (sharing `Runtime.CheckPolicy`) and `mintrun_audit` (redacting command arguments to `argv[0]` plus `[MINTRUN:REDACTED]`).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestExecBlindCleanEnv|TestGCPProviderPhase5|TestKeychainVaultLinuxSecretTool|TestCheckPolicyMatchesExecBlind|TestMCPBridgeGovernanceTools|TestMCPBridgeExecCleanEnv' ./internal/core ./internal/builtin
  ```

### Workstream C — Operational Hardening
- **Files:** `internal/builtin/keychain.go`, `internal/builtin/keychain_integration_test.go`, `internal/builtin/cloudflare.go`, `internal/core/runner.go`, `internal/core/procgroup_unix.go`, `internal/core/procgroup_other.go`, `cmd/mintrun/main.go`
- **Deliverables:**
  1. Pass macOS Keychain secrets over `security -i` `stdin`, read with `-g`, warn on keystore fallback before using the file vault, disable echo on interactive `secret set`, and warn when secrets are passed on `argv`.
  2. Cap child `stdout`/`stderr` at 4 MiB with straddle-safe secret prefix trimming, run Unix children in their own process group, `SIGKILL` the group on timeout or `SIGINT`/`SIGTERM`/`SIGHUP`, and bound pipe wait with `WaitDelay`.
  3. Sign `x-amz-security-token` in SigV4 (verified against the AWS test vector) and report ephemeral AWS STS leases as `revoked: false`.
  4. Require explicit `static` mode requests in `github` and `aws`, matching `CheckPolicy`'s `allow_static` gate, and parse GitHub master secrets identically when `params.installation_id` is set so private keys never reach HTTP headers.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestKeychainVaultMacOSSecurity|TestCLISecretArgvWarning|TestExecBlindOutputCap|TestExecBlindKillsProcessGroup|TestAWSSigV4FixedVector|TestAWSProviderComprehensive|TestGitHubProviderAndJWTSigningComprehensive' ./internal/builtin ./internal/core ./cmd/mintrun
  ```

### Workstream D — GitHub Installation Binding
- **Files:** `internal/core/runner.go`, `internal/builtin/cloudflare.go`, `internal/builtin/mcp.go`
- **Deliverables:**
  1. Add the policy rule `allowed_installations`, enforced in `CheckPolicy` (so `mintrun_policy_check` and `ExecBlind` agree): when set, a request must carry a listed `params.installation_id` (exact match, fail closed when missing).
  2. `GitHubProvider.Mint` refuses a `params.installation_id` that differs from the installation pinned in the master, before any request and without quoting the master; `<app_id>::<pem>` pins none.
  3. Advertise `params` in the MCP `mintrun_exec` / `mintrun_policy_check` input schema.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestGitHubProviderAndJWTSigningComprehensive' ./internal/core ./internal/builtin
  ```

### Workstream E — Secrets Off argv, Bounded Audit Reads & Long Keychain Secrets
- **Files:** `internal/builtin/keychain.go`, `internal/builtin/mcp.go`, `internal/core/runner.go`, `cmd/mintrun/main.go`, and their tests (`internal/builtin/builtin_test.go`, `internal/builtin/keychain_integration_test.go`, `internal/core/core_test.go`, `cmd/mintrun/main_test.go`)
- **Deliverables:**
  1. `OnePasswordVault.SetSecret` pipes a JSON item template to `op item create -`, so the secret travels on `stdin` instead of `argv`. It scrubs the secret from any `op` output it quotes, and archives older items with the same title so `op item get` stays unambiguous. `exec.Command` already refuses an `op` found through a relative `PATH` entry, and a test pins that.
  2. `core.TailAudit` streams `audit.jsonl` line by line and keeps only the last `limit` matches. `mintrun audit` (a raw copy when unfiltered) and MCP `mintrun_audit` both use it, so memory no longer grows with the log.
  3. `keychainSet` splits a secret too long for one `security -i` line into at most 16 items of 1,500 bytes under a fresh random generation. It writes a checksummed header item last, then removes the previous generation's items. `keychainGet` reassembles and verifies the parts, and `DeleteSecret` removes them.
  4. `setEcho` runs a swappable `sttyPath`. A test covers the prompt path with `/dev/null` as `stdin` and a stub `stty`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestKeychainAndOnePasswordVaults|TestTailAudit|TestMCPBridgeGovernanceTools|TestKeychainVaultMacOSSecurity|TestCLISecretPromptHidesEcho|TestCLISubcommandsEndToEnd' ./internal/core ./internal/builtin ./cmd/mintrun
  go test -tags integration -count=1 -v -run TestKeychainVaultRealKeychain ./internal/builtin
  ```

### Workstream F — Keystore Fallback Cleanup
- **Files:** `internal/builtin/keychain.go`, `internal/builtin/builtin_test.go`
- **Deliverables:**
  1. `GetSecret` reads libsecret and the macOS Keychain before the file vault, so an older keystore item used to shadow a secret that `SetSecret` had to store in the file vault. Now, once the file-vault write succeeds, `SetSecret` removes the key from the keystores that failed to store it: the libsecret entry, or the Keychain item and the parts its header names. It uses `deleteKeystores`, which `DeleteSecret` shares. A failed file-vault write deletes nothing.
  2. A delete that finds nothing is fine. Any other delete failure returns an error saying the secret is in the file vault but an older keystore item could not be removed and still takes precedence on read. The error quotes neither the secret nor the helper's `stderr`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestKeychainVaultLinuxSecretTool|TestKeychainVaultMacOSSecurity' ./internal/builtin
  ```

### Workstream G — Stale File-Vault Copy Cleanup
- **Files:** `internal/builtin/keychain.go`, `internal/builtin/builtin_test.go`, `README.md`
- **Deliverables:**
  1. `GetSecret` falls back to the file vault when a keystore lookup fails, so an older `vault.json` copy of a key that libsecret or the Keychain now holds used to come back after a failed lookup. Now a successful keystore store removes that copy through `dropFileCopy`, which calls `deleteFileSecret`. Without `vault.json`, nothing is decrypted or written, so a Keychain-only user needs no `MINTRUN_VAULT_KEY` and sees no warning.
  2. The keystore store has already succeeded, so a copy that cannot be removed (no `MINTRUN_VAULT_KEY`, or a wrong one) only prints a warning that it may remain. The warning names the key, never the secret, and the store still succeeds, because the new keystore item wins on read.
  3. README documents `MINTRUN_FILE_VAULT=1` (file vault only) for a host whose keystore exists but cannot be reached, where `secret set` exits non-zero after a fallback store because removing the older keystore item fails too.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestKeychainVaultLinuxSecretTool|TestKeychainVaultMacOSSecurity' ./internal/builtin
  ```

### Workstream H — Example Plugins
- **Files:** `examples/plugins/bitwarden/`, `examples/plugins/vercel/`, `examples/plugins/postgres-jit/` (each a `plugin.json` plus an executable `run`), `examples/plugins/README.md`, `cmd/mintrun/examples_test.go`
- **Deliverables:**
  1. `[PARALLEL]` Three plugins a user can install right after cloning (`mintrun plugin install ./examples/plugins/<name>`), each in Python 3 with the standard library only, runnable by the macOS system Python 3.9. A helper CLI must resolve to an absolute path, and secrets reach it on `stdin` or in its environment, never on argv.
     - `bitwarden` (vault): stores each master secret as a Secure Note named `mintrun/<key>` through `bw --nointeraction` and an unlocked `BW_SESSION`. More than one item with that name is an error, never a guess. `bw` output is never quoted; its `stderr` is quoted only after the secret is scrubbed from it.
     - `vercel` (provider): mints a Vercel token that expires with the lease, optionally limited to one project (`-scope <project_id>` or `<team_id>/<project_id>`), and deletes it on revoke. The lease ID is the public token ID, and revoke refuses the special ID `current`, which would delete the master token.
     - `postgres-jit` (provider): creates a `LOGIN` role that is a member of the group role named by `-scope` and expires at the lease's end. The master is a `CREATEROLE` role, and the database refuses it when it is a superuser or holds no `ADMIN OPTION` on the group, which PostgreSQL 15 and older would otherwise let `CREATEROLE` grant. The password reaches the server only as a SCRAM-SHA-256 verifier. The child gets only `DATABASE_URL`, because `mintrun` redacts every lease env value from the output. Revoke ends the role's sessions, gives what it owns to the minting role, and drops it.
  2. `[SERIAL]` `cmd/mintrun/examples_test.go` installs each plugin through the CLI and drives `ExecBlind` against a stub `bw`, a stub `psql`, and an `httptest` Vercel API, so the suite stays hermetic (rule 22). It recomputes the SCRAM verifier in Go from the password the child received.
  3. `[SERIAL]` A positive control outside `go test`: on throwaway `postgres:16-alpine` and `postgres:15-alpine` containers with SCRAM on TCP, mint through `./mintrun exec`, log in with the minted credential, and confirm that a wrong password and an expired role are refused, revoke ends an open session and drops the role, and a superuser master or a group without `ADMIN OPTION` is refused.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestExamplePlugins' ./cmd/mintrun
  PATH="/usr/bin:$PATH" go test -count=1 -v -run 'TestExamplePlugins' ./cmd/mintrun   # macOS system Python 3.9
  ```

### Workstream I — Telegram Approval
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/telegram.go`, `internal/builtin/telegram_test.go`, `cmd/mintrun/main.go`
- **Deliverables:**
  1. `[SERIAL]` `core.OSApproval` (the macOS dialog, now exported) reports Deny as `(false, nil)` and a dialog that could not be shown as an error. `core.FirstApproval` asks several approvers at once: the first answer, allow or deny, wins and closes the others; an approver that fails drops out, and only when all fail is their joined error returned.
  2. `[PARALLEL]` `builtin.TelegramApproval` sends the request to a private Telegram chat with Allow and Deny buttons and long-polls `getUpdates` for a tap from that user carrying the message's random nonce. The bot token and user ID are read at approval time from the default vault (`approval-telegram`, never `req.Vault`), every error is scrubbed of the token, and agent-controlled fields are quoted so they cannot forge lines of the message. A Slack incoming webhook is one-way and cannot approve, so it is not built.
  3. `[SERIAL]` `bootRuntime` sets `ApprovalFunc` to `FirstApproval(OSApproval, TelegramApproval(rt))`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestFirstApproval|TestOSApproval|TestCheckPolicyMatchesExecBlind|TestBuiltinGitHubJITEncodingScrubAndHITLApproval' ./internal/core
  go test -count=1 -v -run 'TestTelegramApproval' ./internal/builtin
  ```

---

## 3. Deferred Backlog (Next Actionable Items)

1. **OS Network Sandbox (`no_network: true`), awaiting approval:**
   - Optional per-OS network isolation for the child: a Linux `CLONE_NEWNET` network namespace or a macOS `sandbox-exec` deny-network profile. It must fail closed when requested but unsupported on the host.
   - Open questions before building it: every built-in provider mints a credential for a CLI that calls a network API, so the flag only fits offline commands. A macOS `(deny network*)` profile also blocks Unix sockets (`ssh-agent`, Docker). Many Linux hosts restrict the unprivileged user namespaces that `CLONE_NEWNET` needs.
2. **Linux Host Verification:**
   - Run integration tests against real `secret-tool` on Linux, and `-approve` with Telegram as the only channel (`OSApproval` is macOS-only).
3. **Live Telegram, Bitwarden & Vercel Runs:**
   - Telegram approval, the `bitwarden` vault, and the `vercel` provider have run only against a local Bot API, a stub `bw`, and a local Vercel API. Run each against a throwaway bot or account, with the user's go-ahead, before documenting it as verified.
4. **Two-Way Slack Approval:**
   - Deferred: an incoming webhook only sends, so it cannot carry an answer back. A Slack app could post with `chat.postMessage` and poll `conversations.replies` or `reactions.get` with the standard library; Socket Mode needs WebSockets, which the standard library lacks. Build it when a user asks for Slack.
5. **GCP `token_uri` From the Service-Account Key:**
   - Deferred: only keys outside the default Google universe carry a different `token_uri`, and honoring it also means sending revocation to that universe. Add it when such a key is in use.
