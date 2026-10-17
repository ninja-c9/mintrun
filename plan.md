# `mintrun` Execution Plan & Backlog

> **Harness Spec:** [AGENTS.md](AGENTS.md) · **Latest Release:** `v0.10.0` · **Constraints:** 100% Go `1.24.0` standard library (`0` external dependencies), `> 90%` verified statement coverage measured without build tags.

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
  1. `chat.postMessage` with `channel=<user_id>` posts into the bot's DM with that user and returns the DM's channel ID and the message `ts`. The text is plain (`mrkdwn=false`, `parse=none`, `link_names=false`, no unfurls), quotes every agent-controlled field as Telegram does, and escapes `&`, `<`, `>` to the entities Slack shows as text, so no field can open a `<!channel>`, `<@U…>`, or `<url|label>` sequence. `core.ApprovalText` (Workstream K) cuts the raw text short enough that its escaped form fits in 3,500 bytes, because `chat.update` refuses text over 4,000 characters; escaping after the cut never splits an entity.
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

### Workstream M — Onboarding: `mintrun init` & `mintrun doctor`
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/setup.go` (new), `cmd/mintrun/setup_test.go` (new), `internal/builtin/telegram.go`, `internal/builtin/slack.go`, `internal/builtin/cloudflare.go`, `internal/builtin/keychain.go`, `internal/builtin/telegram_test.go`, `internal/builtin/slack_test.go`, `README.md`
- **Design:**
  - `mintrun init [github|aws|gcp|cloudflare|telegram|slack|policy|mcp]` sets up one piece, or asks about each in turn when given none. It checks every value before storing it, with the provider's own parser where there is one, stores it in the default vault, and asks before replacing a stored secret. Invalid input stores nothing.
    - **GitHub:** App ID and Installation ID are digits; the `.pem` must parse with `ParseRSAPrivateKey`. It stores `<app_id>:<installation_id>:<pem>`, which pins the installation. An empty Installation ID stores `<app_id>::<pem>` and points to `allowed_installations` (rule 27).
    - **AWS:** an `AKIA…` or `ASIA…` access key ID, a 40-character secret read hidden, and a session token, which `ASIA` requires.
    - **GCP:** a service-account JSON file whose `private_key` parses.
    - **Cloudflare:** an API token read hidden.
    - **Telegram:** the bot token is read hidden. `builtin.TelegramLink` prints `https://t.me/<bot>?start=<code>` with a one-time `rand.Text()` code and accepts only a `/start <code>` message, so nobody else who messages the bot gets linked. It shows the sender's name and stores `<user_id>:<bot_token>` only on a yes, then sends a test request through `TelegramApproval`, the path `-approve` uses. Its polling never confirms a callback query, which may answer another pending request (rule 31).
    - **Slack:** the bot token is read hidden and the member ID typed; the test request goes through `SlackApproval`. Slack has no link that proves the member ID is the user's, so `init` asks whether they answered the test themselves and removes the setting on a no.
    - **Policy:** suggests `{"github": {"allowed_scopes": ["<owner/repo>"], "clean_env": true}}` from `git remote get-url origin`. An `owner/*` wildcard only when typed, and never `allow_static`. The remote URL is never printed, since it can carry a token. It creates `policy.json` only when none exists and only after a yes, with `O_EXCL` and mode `0600`: a file made in between is never replaced, and a partial write leaves malformed JSON, which `exec` reads as deny-all. Otherwise it prints the rule and leaves the file alone.
    - **MCP:** the entry is `{"command": "<absolute path>", "args": ["mcp"]}`, from `os.Executable` plus `EvalSymlinks`, and a `go run` build is refused. No entry carries an `env`, so `MINTRUN_VAULT_KEY` never lands in an IDE config.
      - Claude Code: runs `claude mcp add -s user mintrun -- <path> mcp` after a yes and never edits `~/.claude.json`. Without `claude` on `PATH`, it prints the command when `~/.claude.json` exists.
      - Cursor: when `~/.cursor` exists, prints the `cursor://anysphere.cursor-deeplink/mcp/install?config=<base64>&name=mintrun` link, which asks in Cursor before it adds the server, and offers to open it on macOS (elsewhere the link is only printed).
      - Claude Desktop: shows the entry and asks, backs up `claude_desktop_config.json`, then writes it atomically with every other key kept. An existing `mintrun` entry is left alone.
      - Antigravity: offers each of `~/.gemini/antigravity/mcp_config.json` and `~/.gemini/config/mcp_config.json` that exists, merged after a yes as for Claude Desktop. With `~/.gemini/antigravity` but neither file, it points to "Manage MCP Servers → View raw config" and prints the entry.
      - On a file-vault host, it warns that an IDE started from the Dock or an app menu does not get the shell's `MINTRUN_VAULT_KEY`.
  - `mintrun doctor` is read-only and prints names, never values. It checks:
    - the binary: a `go run` build fails; a missing `mintrun` on `PATH`, or a different one, warns;
    - the default vault: the file vault without `MINTRUN_VAULT_KEY` fails;
    - which providers have a stored secret;
    - the approval channels: a malformed `approval-telegram` or `approval-slack` fails;
    - `policy.json`: malformed JSON or an unknown field fails, because the runtime ignores an unknown field and a typo silently drops a limit; a provider with a stored secret and no rule warns;
    - every IDE entry it finds: a missing command, or `MINTRUN_VAULT_KEY` in its `env`, fails.

    Any failure exits 1.
- **Deliverables:**
  1. `[SERIAL]` builtin: export `ParseRSAPrivateKey` and `WriteFileAtomic`; add `ParseTelegramConfig` and `ParseSlackConfig`, which the approval channels and `doctor` share; add `TelegramLink`.
  2. `[SERIAL]` `mintrun doctor` and its hermetic test.
  3. `[SERIAL]` `mintrun init` and its hermetic tests, with a fake `HOME`, `MINTRUN_HOME`, stub `git`, `claude`, `stty` and `open`, and in-process Bot API and Slack Web API stand-ins (an `http.RoundTripper` that refuses every other host).
  4. `[SERIAL]` Mutants run on a copy of the repo, one per security condition.
- **Not built:**
  - `doctor -live` (network calls, 1Password);
  - a web UI;
  - policy rules for providers other than GitHub;
  - Claude Code's project and local scopes.
- **Limits:** the Cursor link, the Claude Code command, and the Antigravity paths are checked against stubs and the vendors' docs only, never a real IDE. `CLAUDE_CONFIG_DIR` is not read, so `doctor` looks for Claude Code's entry in `~/.claude.json` only. The `O_EXCL` guard covers a `policy.json` created between the check and the write, a race the tests do not stage.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIDoctor|TestCLIInit' ./cmd/mintrun
  go test -count=1 -v -run 'TestTelegramLink|TestTelegramApproval|TestSlackApproval' ./internal/builtin
  ```

### Workstream N — Unreadable `policy.json` Fails Closed
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `cmd/mintrun/setup.go`, `cmd/mintrun/setup_test.go`, `README.md`
- **Bug:** `loadPolicyFile` returned on any `os.ReadFile` error, so a `policy.json` that exists but cannot be read (a directory, no read permission, an I/O error) left no rules and no `policyErr`, and every exec was allowed. `doctor` said so: "exec then allows every request".
- **Design:**
  - Only `os.Lstat` reporting `fs.ErrNotExist` means no policy. `Lstat`, because `ReadFile` reports a symlink to a missing file as `ErrNotExist` too, and that symlink is a policy the user meant to have.
  - Any other read error sets `policyErr`, as malformed JSON does, so `CheckPolicy` (rule 16) and `ExecBlind` deny every request with the same reason. The reason and the `stderr` warning keep only the `*fs.PathError` cause, since the reason reaches agents and `audit.jsonl`.
  - `doctorPolicy` decides "no policy" with the same `Lstat` and reports any other read error as a FAIL saying exec denies every request.
- **Deliverables:**
  1. `[SERIAL]` core: the `Lstat` check and the fail-closed read error; `TestCheckPolicyMatchesExecBlind` with a directory, a dangling symlink, a `chmod 000` file when not root, and a missing file that still allows.
  2. `[SERIAL]` cli: `doctorPolicy` and `TestCLIDoctor` (a directory and a dangling symlink, each with the warning; `snapshot` records a symlink's target instead of reading it).
  3. `[SERIAL]` Mutants on a copy of the repo: 7, one per condition (rule 36).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind' ./internal/core
  go test -count=1 -v -run 'TestCLIDoctor' ./cmd/mintrun
  ```

### Workstream O — A Missing Secret Names Its Fix
- **Files:** `internal/builtin/keychain.go`, `internal/builtin/telegram.go`, `internal/builtin/slack.go`, `internal/core/runner.go`, `internal/builtin/builtin_test.go`, `internal/builtin/telegram_test.go`, `internal/builtin/slack_test.go`
- **Design:**
  - The file vault's miss ends with `(run mintrun init <step>)` for a key `mintrun init` stores (`github`, `aws`, `gcp`, `cloudflare`; `approval-telegram` is the `telegram` step and `approval-slack` the `slack` step) and `(run mintrun secret set <key>)` for any other, folding case and spaces as the vault does. It still wraps `ErrSecretNotFound`, which `doctor` reads as not set.
  - Only the vault can tell a miss from a failure, so callers add no hint. `ExecBlind` drops the `secret set` hint it added to every vault error, which a miss would now repeat and which told a user with a wrong `MINTRUN_VAULT_KEY` to store the secret again; the Telegram and Slack approvals drop theirs.
  - 1Password adds none: `op` fails the same way for a miss, a locked or signed-out account, and an ambiguous title, its `stderr` has never been checked against a real `op` (rule 28), and the error already quotes that `stderr`, scrubbed. A plugin vault's error keeps its own text (`bitwarden` names `bw sync`).
- **Deliverables:**
  1. `[SERIAL]` `setupHint` in the file vault, and the callers' hints removed.
  2. `[SERIAL]` `TestSecretNotFoundHint` and the exact not-configured errors in `TestTelegramApproval` and `TestSlackApproval`; mutants run on a copy of the repo.
- **Not built:** `init` and `secret set` store into the default vault, so with `MINTRUN_VAULT` naming another vault, a request that picks `keychain` gets a command that stores elsewhere. (`secret check` dropped the error and showed neither the hint nor a vault failure; Workstream P fixes it.)
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestSecretNotFoundHint|TestTelegramApproval|TestSlackApproval' ./internal/builtin
  ```

### Workstream P — `secret check` Shows the Vault's Error
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`
- **Design:**
  - A miss (`errors.Is(err, builtin.ErrSecretNotFound)`) still says `NOT configured` and adds the vault's error, so the hint from Workstream O shows once.
  - Any other error says the vault could not be read and adds its error, so a wrong `MINTRUN_VAULT_KEY` is no longer reported as a missing secret. An empty value still says `NOT configured`. All three exit 1.
  - The vault's error holds no secret: the file vault's quotes no stored value (a keystore failure only warns, rule 18), 1Password's quotes `op`'s `stderr` and never its `stdout`, and a plugin vault's is the plugin's own (rule 32). `ExecBlind` already returns the same error to agents. A 1Password miss reads as a vault that could not be read, because `op` fails the same way for a miss and a locked account.
- **Deliverables:**
  1. `[SERIAL]` the `check` branch in `cmd/mintrun/main.go`.
  2. `[SERIAL]` `TestCLISecretCheckReportsVaultError` (a miss, a file vault opened with a wrong `MINTRUN_VAULT_KEY`, an empty value from a plugin vault); mutants run on a copy of the repo.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLISecretCheckReportsVaultError' ./cmd/mintrun
  ```

### Workstream Q — `secret check` Prints No Length
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`
- **Design:**
  - On success `secret check` printed `(length=<n> chars, value hidden)`. The length comes from the secret, and `doctor` never prints one (rule 35). It narrows a guess and tells one kind of credential from another.
  - The line now names only the key and the vault: `Secret "<key>" is configured in vault "<vault>" (value hidden).`, exit 0. The three failure paths from Workstream P are unchanged.
- **Deliverables:**
  1. `[SERIAL]` the success line in the `check` branch of `cmd/mintrun/main.go`.
  2. `[SERIAL]` `TestCLISecretCheckConfigured` (the exact line, exit 0, an empty `stderr`); 1 mutant (the length printed again) run on a copy of the repo.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLISecretCheckConfigured' ./cmd/mintrun
  ```

### Workstream R — Plugin JSON Errors Never Quote `stdout`
- **Files:** `internal/core/plugin.go`, `internal/core/core_test.go`
- **Design:**
  - `ExternalPlugin.call` wrapped the `json.Unmarshal` error, and Go's JSON errors quote their input: a bare secret on a plugin's `stdout` showed its first character (`invalid character 'h' looking for beginning of value`), and a string in `lease.expires_at`, a `time.Time`, showed whole, twice (`parsing time "…" as "2006-01-02T15:04:05Z07:00": cannot parse "…" as "2006"`). `Scrub` knows the master, plus a lease's secrets once the reply has decoded, so the text reached `secret check`, `ExecBlind`, and MCP, and a mint's also reached `audit.jsonl`.
  - The error is now the fixed `plugin "<name>" returned an invalid JSON response`, which quotes nothing from `stdout`. It says "invalid JSON response" rather than "not valid JSON", because a reply with a mistyped field is valid JSON. The `stderr` and `resp.Error` paths are unchanged: the plugin scrubs those itself (rule 32).
- **Deliverables:**
  1. `[SERIAL]` the `json.Unmarshal` branch in `internal/core/plugin.go`.
  2. `[SERIAL]` `TestPluginInvalidJSONNeverQuotesStdout` (a plugin vault whose reply is a bare canary, a plugin provider whose lease holds the canary in `expires_at`: the exact `ExecBlind` error, no canary, and the audited mint error); the re-wrap mutant runs on a copy of the repo.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestPluginInvalidJSONNeverQuotesStdout' ./internal/core
  ```

### Workstream S — The Approval Dialog Defaults to Deny and Shows the Vault and Working Directory
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/telegram_test.go`, `internal/builtin/slack_test.go`
- **Design:**
  - The dialog's default button was "Allow", so a stray Return approved the request. Deny is now both the default and the cancel button, so Return and Esc both raise `-128`, which stays the one `(false, nil)` answer (rule 31).
  - `ApprovalText` did not show `ExecRequest.Vault` or `ExecRequest.WorkingDir`, which an agent sets through MCP `mintrun_exec` (`vault`, `cwd`) and a user through `-vault` and `-cwd`. A `Vault:` line now follows the provider and a `Working directory:` line ends the text, both `strconv.Quote`d (rule 4). An empty value shows `(not set: the default vault)` or `(not set: mintrun's own)`, unquoted, so no agent value can pass for it. Neither is resolved, so no local path reaches Telegram or Slack unless the request set one.
  - The working directory comes after the command, so a long command pushes it behind the TRUNCATED warning, which already says to deny. The caps are unchanged: 1,000 bytes in the dialog, 3,500 in Telegram, and Slack per rule 34.
  - The new `Vault:` line moved the long request's cut onto a rune boundary, and `TestOSApproval` stopped catching a missing UTF-8 trim. The long check now runs with and without a 1-byte pad, so one of the two cuts always lands inside a rune.
- **Deliverables:**
  1. `[SERIAL]` the dialog script and `ApprovalText` in `internal/core/runner.go`.
  2. `[SERIAL]` `TestOSApproval` (the script with Deny as the default, the not-set text, a working directory holding a fake `Working directory:` line and U+202E written as escapes, the padded long check) and the expected text in `TestTelegramApproval` and `TestSlackApproval`; 13 mutants run on copies of the repo.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestOSApproval' ./internal/core
  go test -count=1 -v -run 'TestTelegramApproval|TestSlackApproval' ./internal/builtin
  ```

### Workstream T — CLI Shims (`mintrun shim`: Block & Redirect + Auto-Wrap)
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/setup.go`, `cmd/mintrun/shim.go` (new), `cmd/mintrun/shim_test.go` (new), `README.md`, `AGENTS.md`, `plan.md`, `checks.md`, `progress.md`
- **Design:**
  - AI agents in a shell invoke `gh`, `aws`, `gcloud`, `wrangler`, `vercel`, and `psql` by bare name, bypassing `mintrun_exec` and `mintrun exec`. `mintrun shim` places symlinks to this `mintrun` binary in `<home>/shims/{gh,aws,gcloud,wrangler,vercel,psql,mintrun}` (`0700`) and stores per-tool settings in `<home>/shims/config.json` (`0600`, written atomically via `builtin.WriteFileAtomic`, decoded strictly with `DisallowUnknownFields`).
  - When `filepath.Base(os.Args[0])` (without `.exe`) is one of the six shimmed CLI names (`gh`, `aws`, `gcloud`, `wrangler`, `vercel`, `psql`), `main` dispatches directly to `runShim(ctx, rt, tool, os.Args[1:])`:
    - **Fail-closed config loading:** Only a missing `<home>/shims/config.json` (checked via `os.Lstat` for `fs.ErrNotExist`, rule 36) means default settings (`mode: "block"` for every tool). An unreadable file (a directory, a dangling symlink, `chmod 000`), malformed JSON, an unknown field (`DisallowUnknownFields`), an unknown tool key, or a `mode` other than `""`, `"block"`, or `"auto"` refuses execution with exit 126, quoting only the `*fs.PathError` cause and never a local path.
    - **Environment tightening only:** `MINTRUN_SHIM_MODE=block` forces `block` mode even when `config.json` sets `"mode": "auto"`, whereas `MINTRUN_SHIM_MODE=auto` never loosens `"block"` to `"auto"` (an agent running in bash controls its own environment; rule 11).
    - **Mode 1 — `block` (default):** refuses direct execution with exit 126 without opening a vault, minting, or running the underlying CLI, and prints a JSON error on `stderr` that names both the `mintrun_exec` MCP tool and the exact `mintrun exec -provider <provider> -scope <scope> -perms <perms> -- <tool> ...` command (using the inferred `owner/repo` scope for `gh` when available, never printing the git remote URL).
    - **Mode 2 — `auto` (`"mode": "auto"` in `config.json`):** resolves the real `<tool>` binary from `PATH` skipping `<home>/shims` (both raw and `EvalSymlinks`-resolved) and rejecting any relative `PATH` entry (rule 14). Strips `<home>/shims` from `PATH`, infers `scope` (configured `scope`, else `-R`/`--repo` flag or `git remote get-url origin` for `gh`, else a single non-wildcard `allowed_scopes[0]` from `rt.Policies[provider]`) and `permissions` (configured `permissions`, else read-only defaults for read subcommands, else non-wildcard `allowed_permissions` from `rt.Policies[provider]`), and runs `rt.ExecBlind` with `Command: append([]string{realBin}, args...)` and `Approve: cfg.Approve`.
  - **No recursion under `mintrun exec` or `mintrun mcp`:** `main` saves the caller's original `PATH` for `doctor` and `shim list`, and strips `<home>/shims` from `os.Getenv("PATH")` before `cmdExec`, `cmdMCP`, or `runShim` invokes `ExecBlind`, so `ExecBlind` always resolves the real underlying CLI binary instead of re-entering `<home>/shims/<tool>`.
  - **Subcommands:**
    - `mintrun shim` / `mintrun shim list` (`ls`): prints a table of the six tools (`TOOL`, `PROVIDER`, `SHIM`, `MODE`, `TARGET`) without changing any file.
    - `mintrun shim install [-mode block|auto] [-scope <s >] [-perms <p1,p2>] [-approve] [tool...]`: validates flags and tool names, refuses a `go run` binary (`mintrunPath`, rule 35), refuses `-scope` or `-perms` when installing multiple tools at once, creates `<home>/shims`, atomically links `mintrun` and each selected tool to `self`, updates `<home>/shims/config.json`, and prints the `export PATH="<home>/shims:$PATH"` instruction.
    - `mintrun shim remove [tool...]` (`rm`): removes the named tool symlinks (or all six when none are given) and their entries in `<home>/shims/config.json`.
  - **`mintrun doctor` (`doctorShims`):** when `<home>/shims` exists, checks `config.json` and each tool symlink (`FAIL` on broken/unreadable `config.json` or missing symlink target; `warn` when a symlink points to another binary or when `<home>/shims` is not ahead of the real binary's directory on `PATH`; `ok` when active).
- **Deliverables:**
  1. `[SERIAL]` `cmd/mintrun/shim.go`, `cmd/mintrun/main.go`, and `cmd/mintrun/setup.go` (`doctorShims`).
  2. `[SERIAL]` `cmd/mintrun/shim_test.go`: hermetic tests for `mintrun shim install|list|remove`, `block` mode (exit 126, redirect hint, `MINTRUN_SHIM_MODE=auto` cannot loosen `block`), `auto` mode (`ExecBlind` delegation, `MINTRUN_SHIM_MODE=block` tightens `auto` to `block`, `gh` scope/perm inference, non-recursive `mintrun exec -- gh ...` with `<home>/shims` first on `PATH`, relative `PATH` rejection, fail-closed `shims/config.json`), and `doctorShims`.
  3. `[SERIAL]` Mutants run on a copy of the worktree, one per security condition.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIShim|TestCLIDoctor' ./cmd/mintrun
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
