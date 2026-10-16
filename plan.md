# `mintrun` Execution Plan & Backlog

> **Harness Spec:** [AGENTS.md](AGENTS.md) · **Latest Release:** `v0.9.0` · **Constraints:** 100% Go `1.24.0` standard library (`0` external dependencies), `> 90%` verified statement coverage measured without build tags.

---

## 1. Standard Acceptance Checks (`<layer_3_tools_hooks>`)

Every change to `cmd/`, `internal/`, or `examples/` must pass the following verification pipeline before completion:

1. **Format & Static Analysis:**
   ```bash
   gofmt -s -l cmd internal examples && go vet ./...   # never gofmt . (rule 17)
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
  2. `[PARALLEL]` `builtin.TelegramApproval` sends the request to a private Telegram chat with Allow and Deny buttons and long-polls `getUpdates` for a tap from that user carrying the message's random nonce. The bot token and user ID are read at approval time from the default vault (`approval-telegram`, never `req.Vault`), every error is scrubbed of the token, and agent-controlled fields are quoted so they cannot forge lines of the message. A Slack incoming webhook is one-way and cannot approve; two-way Slack came later, in Workstream L.
  3. `[SERIAL]` `bootRuntime` sets `ApprovalFunc` to `FirstApproval(OSApproval, TelegramApproval(rt))`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestFirstApproval|TestOSApproval|TestCheckPolicyMatchesExecBlind|TestBuiltinGitHubJITEncodingScrubAndHITLApproval' ./internal/core
  go test -count=1 -v -run 'TestTelegramApproval' ./internal/builtin
  ```

### Workstream J — Install Example Plugins by Name
- **Files:** `examples/plugins/embed.go`, `cmd/mintrun/main.go`, `cmd/mintrun/examples_test.go`, `README.md`, `examples/plugins/README.md`
- **Deliverables:**
  1. `[SERIAL]` `examples/plugins/embed.go` embeds the three example plugins in the binary, and `mintrun plugin install <name>` installs one through `core.InstallPlugin` from a temporary copy that it removes. A bare name built into the binary wins over a directory of that name in the working directory, which installs by its path (`./bitwarden`).
  2. `[SERIAL]` `TestPluginInstallCatalog` installs every directory under `examples/plugins/` by name and compares the installed files with the source byte for byte.
- **Not built:** a remote index for third-party plugins. A plugin from outside this repo still installs from a directory, or from an `https://` URL with `#sha256=`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestPluginInstallCatalog|TestExamplePlugins' ./cmd/mintrun
  ```

### Workstream K — Quoted Approval Text
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/telegram.go`
- **Deliverables:**
  1. `[SERIAL]` `core.ApprovalText` builds the text every approver shows: provider, scope, permissions, params (sorted), and each argv element `strconv.Quote`d, cut on a UTF-8 boundary with a TRUNCATED warning. `OSApproval` passes it, cut at 1,000 bytes, to `display dialog` through `%q`, so a newline in an argument no longer fakes a line of the dialog, and permissions and params now show. `telegramText` calls it with its 3,500-byte cap and sends the same message as before.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestOSApproval' ./internal/core
  go test -count=1 -v -run 'TestTelegramApproval' ./internal/builtin
  ```

### Workstream L — Slack Approval
- **Files:** `internal/builtin/slack.go`, `internal/builtin/slack_test.go`, `cmd/mintrun/main.go`
- **Design** (checked against Slack's Web API reference on 2026-10-16): Slack's interactive buttons post the tap to a public Request URL, and Socket Mode needs a WebSocket client, which the standard library lacks. So `mintrun` posts the request and polls for a reaction, which needs no endpoint of its own:
  1. `chat.postMessage` with `channel=<user_id>` posts into the bot's DM with that user and returns the DM's channel ID and the message `ts`. The text is plain (`mrkdwn=false`, `parse=none`, `link_names=false`, no unfurls), quotes every agent-controlled field as Telegram does, and escapes `&`, `<`, `>` to the entities Slack shows as text, so no field can open a `<!channel>`, `<@U…>`, or `<url|label>` sequence. `core.ApprovalText` (Workstream J) cuts the raw text short enough that its escaped form fits in 3,500 bytes, because `chat.update` refuses text over 4,000 characters; escaping after the cut never splits an entity.
  2. `reactions.add` puts ✅ (`white_check_mark`) and ❌ (`x`) on the message, so one tap answers. Both must succeed before polling starts.
  3. `reactions.get` with `full=true` (the complete `users` list) runs every 3 s. Only a reaction whose `users` holds the stored user ID counts, so the bot's own reactions never do, and ❌ wins over ✅. A config naming the bot itself therefore reads as both, a denial.
  4. `chat.update` replaces the prompt with the outcome, best effort, even after the context is cancelled.
  - The config is `<user_id>:<bot_token>` in the default vault's `approval-slack` (never `req.Vault`), for a bot with the `chat:write`, `reactions:read`, and `reactions:write` scopes. The token travels in `Authorization: Bearer` on form-encoded POSTs.
  - Failures: HTTP 429 waits `Retry-After` seconds (at least the poll interval) before the next poll. A network error, HTTP 5xx, or malformed reply is retried. An API error (`ok: false`, such as `missing_scope`, `invalid_auth`, or `channel_not_found`) ends the wait with that error, because retrying will not fix it. No answer within 10 minutes, or a cancelled context, is an error. None of these is ever an approval, and every error is scrubbed of the token.
- **Limits:** an answer is seen within about 3 s, not at once, and each pending request spends about 20 `reactions.get` calls a minute from the app's Tier 3 quota (50+ a minute, shared by parallel requests). The request (provider, scope, permissions, params, argv) passes through Slack's servers and stays in the DM. Other emoji are ignored. Tested only against a mock Slack Web API, never a real workspace.
- **Deliverables:**
  1. `[SERIAL]` `builtin.SlackApproval(rt)` and its hermetic test against an `httptest` Slack API, with one mutant per security condition run on a copy of the repo.
  2. `[SERIAL]` `bootRuntime` sets `ApprovalFunc` to `FirstApproval(OSApproval, TelegramApproval(rt), SlackApproval(rt))`, and the `-approve` help names `approval-slack`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestSlackApproval|TestTelegramApproval' ./internal/builtin
  ```

---

## 3. Deferred Backlog (Next Actionable Items)

1. **Child Sandbox: Keep the Blind Command Out of the Vault, awaiting approval:**
   - **Goal:** while the blind command runs, it cannot read `mintrun`'s home (`~/.mintrun` or `MINTRUN_HOME`: `vault.json`, `policy.json`, `audit.jsonl`, plugins) or the user's Keychain, which closes two routes README §5 lists. It is not isolation: the command still runs as the user, keeps the network and the rest of `HOME`, and can leave something behind (a shell profile line, a LaunchAgent) that runs later outside the sandbox. The docs must say so (rule 23).
   - **Switch:** policy `"sandbox": true` per provider, and a request flag (CLI `-sandbox`, MCP `sandbox`) that can only tighten it, like `clean_env` (rule 11). The check lives in `CheckPolicy` (rule 16): a sandbox the host cannot provide is a denial before any vault opens.
   - **macOS:** run `/usr/bin/sandbox-exec -p <profile> -D MINTRUN_DIR=<home> -D KEYCHAINS=<~/Library/Keychains> -- <argv>`, with both paths resolved by `filepath.EvalSymlinks` first, because the profile matches real paths. `sandbox-exec` is deprecated but still ships; a missing one is a denial.
     ```
     (version 1)
     (allow default)
     (deny file-read* file-write* (subpath (param "MINTRUN_DIR")))
     (deny file-read* file-write* (subpath (param "KEYCHAINS")))
     (deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd.xpc"))
     ```
   - **Spike (2026-10-16, macOS 27.0 build 26A428, a throwaway `HOME`; no real vault or Keychain item was read):**
     - `pass` The first rule alone: reading `vault.json`, listing the directory, and writing into it fail (exit 1); other `HOME` files, a local HTTP request (200), and `git` still work.
     - `pass` The whole profile: `security find-generic-password` can no longer start a search (a parameter error on `stderr`; the exit code stays 44, so only `stderr` tells it from a miss); TLS through Go's platform verifier and `curl` (200), `git`, and `python3` still work.
     - `pass` The Keychain file rule without the two `mach-lookup` names changed nothing a probe could see, so those names are required.
     - `pass` The child could not read its parent's environment: `ps -E -ww -p $PPID` and `sysctl KERN_PROCARGS2` on the parent returned 319 to 742 bytes without the canary, while the same reads of the child's own pid returned 5,012 bytes with it (the positive control), also outside the sandbox the test shell ran in. README §5 and rule 23 now say this for macOS 27.0 only; older releases and a debugger attach are untested.
     - `unresolved` A real Keychain item becoming unreadable inside the profile: needs a throwaway item, read once outside (found) and once inside (refused), in a `-tags integration` test run with the user's go-ahead.
   - **Cost:** inside the sandbox, tools that keep their own credential in the Keychain (`gh` with a stored token, `git` with `osxkeychain`) fail; the lease's environment (`GH_TOKEN`, `CLOUDFLARE_API_TOKEN`, …) replaces them.
   - **Linux (design only):** Landlock only grants access, so hiding one directory means granting every other path. Instead `mintrun` re-executes itself in new user and mount namespaces (`SysProcAttr.Cloneflags`), mounts an empty `tmpfs` over its home, and then `exec`s the command. Ubuntu 24.04 blocks unprivileged user namespaces by default (`kernel.apparmor_restrict_unprivileged_userns=1`), so the check must probe and deny. libsecret answers over the D-Bus session bus, which a mount namespace does not hide, so `sandbox` is a denial on Linux until a test proves `secret-tool lookup` fails inside. `/proc/$PPID/environ` stays readable unless `mintrun` makes itself non-dumpable (`PR_SET_DUMPABLE`, untested).
   - **Tests:** the denials (no `sandbox-exec`, Linux) pinned in `TestCheckPolicyMatchesExecBlind`; a stub `sandbox-exec` that records the profile and the resolved paths; a `-tags integration` test that runs the real profile against a throwaway home and Keychain item.
   - **`no_network` stays open:** every built-in provider's CLI calls a network API, so it fits offline commands only, and a macOS `(deny network*)` also blocks Unix sockets (`ssh-agent`, Docker).
2. **Linux Host Verification:**
   - Run integration tests against real `secret-tool` on Linux, and `-approve` with Telegram and Slack as the only channels (`OSApproval` is macOS-only).
3. **Live Runs: Telegram, 1Password, Bitwarden & Vercel:**
   - These have run only against stand-ins (a local Bot API, a mock `op`, a stub `bw`, a local Vercel API). The user runs each check below with a throwaway bot or account of their own, and `checks.md` §3 turns `pass` only on that run's output.
   - **Telegram:** create a bot with @BotFather and send it `/start`, store `<user_id>:<bot_token>` at the hidden prompt of `./mintrun secret set approval-telegram`, then run `./mintrun exec -approve -provider <p> -scope <s> -- true` three times, with `<p>` a provider whose master secret is already stored: tap Allow (the command runs), tap Deny (it does not), and on macOS click the dialog first (the Telegram message is edited to show the outcome). `audit.jsonl` gets one entry per run, and no output holds the token.
   - **1Password:** after `op signin`, `MINTRUN_VAULT=1password ./mintrun secret set mintrun-live-test`, then `secret check`, `secret set` again (one active item remains and the older one is archived), and `secret delete`.
   - **Bitwarden:** `./mintrun plugin install bitwarden`, `export BW_SESSION="$(bw unlock --raw)"`, then `MINTRUN_VAULT=bitwarden ./mintrun secret set mintrun-live-test`, `secret check`, and `secret delete` (the note moves to the trash).
   - **Vercel:** `./mintrun plugin install vercel`, store a Vercel token with `./mintrun secret set vercel`, then `./mintrun exec -provider vercel -ttl 300 -- npx vercel whoami` (the minted token works) and `-- sleep 60`: the account's token list shows the new token while the command runs, and it is gone after the command exits.
4. **Live Slack Approval Run:**
   - Slack approval has run only against a local Slack Web API. The user runs this check with a throwaway workspace and app of their own, and `checks.md` §3 "Live Slack Web API" turns `pass` only on that run's output.
   - Create the app and store `<user_id>:<bot_token>` at the hidden prompt of `./mintrun secret set approval-slack` as README "Approve From Your Phone" says, then run `./mintrun exec -approve -provider <p> -scope <s> -- true` three times, with `<p>` a provider whose master secret is already stored: react ✅ (the command runs), react ❌ (it does not), and on macOS click the dialog first (the Slack message is edited to show the outcome). `audit.jsonl` gets one entry per run, and no output holds the token.
5. **GCP `token_uri` From the Service-Account Key:**
   - Deferred: only keys outside the default Google universe carry a different `token_uri`, and honoring it also means sending revocation to that universe. Add it when such a key is in use.
6. **Team Relay (`mintrun relay`), design only, awaiting approval:**
   - **Goal:** one server holds the master secrets, the policy, and the audit log; a developer's laptop holds no master and receives only leases.
   - **Server:** `mintrun relay -listen <addr>` serves HTTPS only (`crypto/tls`, TLS 1.3). Each laptop authenticates with its own client certificate (mutual TLS) or bearer token, revocable one device at a time. `POST /v1/mint` takes an `ExecRequest` and runs `CheckPolicy`, approval (Telegram, or Slack once built: the server has no screen for the macOS dialog), `Mint`, and the audit entry, then returns the lease's `env`, the values to redact, the lease ID, and the expiry; `Lease.RevokeSecret` stays on the server. `POST /v1/revoke` takes the lease ID, the exit code, and `truncated`. The server also revokes each lease when it expires, so a laptop that crashes or goes offline never keeps a credential past its TTL.
   - **Client:** `mintrun exec -relay https://<host>` (or `MINTRUN_RELAY`) mints through the server, runs the command locally with the lease, scrubs the output against the lease values, and reports the exit to the server.
   - **Limits the docs must state:**
     - The lease reaches the laptop: the command, and anything else running as that user, can use it until it expires or is revoked.
     - The server sees only what the laptop says it will run, so `blocked_commands` and the approval message are only as honest as the client. The limits a laptop cannot dodge are the ones applied at mint time: provider, scope, permissions, TTL, installations.
     - Static mode is always refused over the relay, because it would send the master itself to the laptop.
   - **Open questions:** who enrolls and retires devices, per-device rate limits, where the server keeps masters (the Keychain on macOS, the file vault on Linux), and failing closed while the server is down.
   - **First slice:** per-device tokens, no static mode, Telegram approval, tests against `httptest.NewTLSServer`.
