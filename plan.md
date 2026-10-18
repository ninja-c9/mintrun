# `mintrun` Execution Plan & Backlog

> **Harness Spec:** [AGENTS.md](AGENTS.md) · **Latest Release:** `v0.14.0` · **Constraints:** 100% Go `1.24.0` standard library (`0` external dependencies), `> 90%` verified statement coverage measured without build tags.

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
5. **Opt-In macOS Integration Checks (macOS only):**
   ```bash
   go test -tags integration -count=1 -v -run TestKeychainVaultRealKeychain ./internal/builtin   # real login Keychain
   go test -tags integration -count=1 -v -run '^TestSandboxHidesHome$' ./internal/core        # real sandbox-exec, throwaway folders
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

### Workstream U — An Agent Cannot Pick the Vault
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/mcp.go`, `internal/builtin/builtin_test.go`, `README.md`
- **Gap:** `mintrun_exec` and `mintrun_policy_check` decode their arguments straight into `core.ExecRequest`, so an agent could send `vault` and pick the vault its master secret is read from, although the tools' input schema and README's MCP table never listed it. No policy rule gates the vault: policy is per provider.
- **Design:**
  - The vault is the operator's choice: `MINTRUN_VAULT` (or `keychain`) for `mintrun mcp`, `-vault` on the CLI. The schema still leaves `vault` out.
  - The bridge sets `ExecRequest.FromAgent` after decoding, for both tools. The field is `json:"-"`, so no argument reaches it. `CheckPolicy` denies a request with `FromAgent` and a non-empty `Vault` right after request validation, so `ExecBlind` audits the denial with exit 126 before any vault opens, and `mintrun_policy_check` returns the same reason (rule 16). The CLI never sets the flag, so `-vault` works as before.
  - The reason quotes the vault the agent sent (the agent's own input, never a secret) and names `MINTRUN_VAULT`.
- **Deliverables:**
  1. `[SERIAL]` core: `FromAgent` and the denial in `CheckPolicy`; `TestCheckPolicyMatchesExecBlind` with an agent's request naming a vault (denied by both) and the same request without the flag (allowed, as the CLI's `-vault`).
  2. `[SERIAL]` builtin: the bridge sets the flag; `TestMCPBridgeRefusesVault` (`mintrun_policy_check` and `mintrun_exec` naming the vault the server already uses give the same exact reason, the exec is a tool error audited with exit 126, and the same request without `vault` runs).
  3. `[SERIAL]` Mutants on a copy of the repo, each failing a test: the denial removed, the flag left unset by `mintrun_exec` or by `mintrun_policy_check`, the check in `ExecBlind` only, the check in the bridge only (not audited), the flag ignored (the CLI's `-vault` denied).
- **Not built:** `mintrun_exec` also decodes `timeout_seconds` and `approve`, which the schema and README do not list either; `approve` can only add a human check, but `timeout_seconds` lifts the 5-minute default. Workstream V closes it.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind' ./internal/core
  go test -count=1 -v -run 'TestMCPBridgeRefusesVault|TestMCPBridgeGovernanceTools' ./internal/builtin
  ```

### Workstream V — An Agent Cannot Set the Timeout
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/mcp.go`, `internal/builtin/builtin_test.go`, `README.md`
- **Gap:** `mintrun_exec` decodes its arguments straight into `core.ExecRequest`, so besides `vault` (Workstream U) an agent could send `timeout_seconds` and `approve`, which neither the input schema nor README's MCP table listed. `approve: true` only adds a human check, but `timeout_seconds` lifted the 5-minute limit to whatever the agent asked for.
- **Design:**
  - An agent's command runs with the 5-minute limit, like the CLI's: no `mintrun` command takes a time limit. `CheckPolicy` denies a request with `FromAgent` and a non-zero `TimeoutSec` right after the vault check and before the provider's `policy.json` rule is looked up, so it holds for a provider with no rule. `ExecBlind` audits the denial with exit 126 before any vault opens, and `mintrun_policy_check` returns the same reason (rule 16).
  - A negative value is denied too, though `ExecBlind` would read it as the default: the rule is that an agent sets none, not that it may set a harmless one. The reason quotes the number the agent sent and says to omit the field.
  - `approve` goes into both tools' schema, since it can only add a check: `MINTRUN_APPROVE=1` and policy `require_approval` ask whatever it says. The `mintrun_exec` description says the command is killed after 5 minutes.
  - `TestMCPExecSchema` keeps the schema and the struct in step: it walks `core.ExecRequest`, the embedded `MintRequest` included, and requires both tools to list every field it decodes except `vault` and `timeout_seconds`.
- **Deliverables:**
  1. `[SERIAL]` core: the denial in `CheckPolicy`; `TestCheckPolicyMatchesExecBlind` with an agent's `timeout_seconds` of 3600 and -1 (denied by both), both agent refusals for a provider `policy.json` has no rule for, and a library caller's `TimeoutSec` (allowed).
  2. `[SERIAL]` builtin: `approve` in the schema and the 5-minute limit in the tool description; `TestMCPBridgeRefusesTimeout` (both tools give the same exact reason, the exec is a tool error audited with exit 126, and the same request without `timeout_seconds` runs; it shares `mcpRefusal` with `TestMCPBridgeRefusesVault`); `TestMCPExecSchema`.
  3. `[SERIAL]` Mutants on a copy of the repo, each failing a test: the denial removed, in `ExecBlind` only, or in the bridge only (not audited); the flag ignored; `> 0` for `!= 0`; the reason without the value; `approve` left out of the schema, or `timeout_seconds` or `vault` put in; a new `ExecRequest` or `MintRequest` field neither listed nor refused; either tool not setting the flag; `mintrun_policy_check` given its own schema; the `json:"-"` tag dropped; the timeout or the vault check moved under a provider's rule.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind' ./internal/core
  go test -count=1 -v -run 'TestMCPBridgeRefusesVault|TestMCPBridgeRefusesTimeout|TestMCPExecSchema|TestMCPBridgeGovernanceTools' ./internal/builtin
  ```

### Workstream W — Shim Profile Edits Ask First
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/shim.go`, `cmd/mintrun/shim_test.go`, `README.md`, `AGENTS.md`, `plan.md`, `checks.md`, `progress.md`
- **Gap:** `c5cea73` made `shim install` add its PATH line to `~/.zshenv` and `~/.zshrc` (and to `~/.zprofile` and `~/.bashrc` when they exist), and `shim remove` take it out, with no question and no backup, which rule 35 requires before writing a user's file. It replaced a linked profile (dotfiles) with a regular file, removal dropped any line that held the marker, nothing documented the edits, and `cmd/mintrun` coverage fell from 94.4% to 93.8%.
- **Design:**
  - `shim install` reads the profiles before it links anything, then shows the line and the profiles and asks `[y/N]` through `wizard.confirm`; `shim remove` asks the same way once no shim is left. Any answer but `y` or `yes` changes nothing, and the line is already on screen to add by hand.
  - On a yes, each profile is read again, and one changed while the question waited stops `mintrun`. Each existing profile is copied to `<file>.bak-<time>` with its mode, then written atomically with its mode (`0600` when new).
  - A profile is resolved with `filepath.EvalSymlinks` and written where it lives; a link that cannot be followed is skipped.
  - Only the exact `shimProfileLine` moves or goes. The line goes last, after a newline when the file's last line has none.
  - `main` passes its signal context to `cmdShim`, so Ctrl-C at the question stops `mintrun`.
- **Deliverables:**
  1. `[SERIAL]` Subtests in `cmd/mintrun/shim_test.go` that fail on `c5cea73`.
  2. `[SERIAL]` `cmd/mintrun/shim.go` and `cmd/mintrun/main.go`.
  3. `[SERIAL]` 25 mutants on a copy, each failing `TestCLIShim`, with controls: an unchanged copy and a comment-only change pass, and a planted compile error reports a build failure.
  4. `[SERIAL]` README, AGENTS.md rule 40, `checks.md`, `progress.md`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIShim' ./cmd/mintrun
  ```

### Workstream Y — Sandbox the Blind Command on macOS
> Planned as Workstream X with rule 41; `main` gave X to the macOS app hooks (§4) and rules 41 and 42 to them, so this is Workstream Y with rule 43.

- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/core/sandbox_integration_test.go`, `internal/builtin/mcp.go`, `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`, `README.md`, `AGENTS.md`, `plan.md`, `checks.md`, `progress.md`
- **Gap:** the blind command runs as the user, so a command written to steal secrets can read `mintrun`'s home (`vault.json`, `policy.json`, `audit.jsonl`, plugins) or ask the Keychain for the item that holds a master secret (rule 23, README §5). Nothing closed either route.
- **Design:**
  - Policy `"sandbox": true` per provider, the CLI's `-sandbox`, and MCP `sandbox` turn the sandbox on. A request can only add it, like `clean_env` (rule 11). `PolicyDecision.Sandbox` reports it, so `mintrun_policy_check` shows it.
  - On macOS the command runs as `/usr/bin/sandbox-exec -p <profile> -D MINTRUN_DIR=<home> -D KEYCHAINS=<$HOME/Library/Keychains> -- <command> <args>`. The profile allows everything else and denies file reads and writes under both folders, plus the `mach-lookup` of 9 Security services:
    ```
    (version 1)
    (allow default)
    (deny file-read* file-write* (subpath (param "MINTRUN_DIR")))
    (deny file-read* file-write* (subpath (param "KEYCHAINS")))
    (deny mach-lookup
      (global-name "com.apple.SecurityServer")
      (global-name "com.apple.securityd.xpc")
      (global-name "com.apple.securityd.general")
      (global-name "com.apple.securityd.ckks")
      (global-name "com.apple.securityd.aps")
      (global-name "com.apple.securityd.sos")
      (global-name "com.apple.security.octagon")
      (global-name "com.apple.security.kcsharing")
      (global-name "com.apple.security.escrow-update"))
    ```
  - `sandbox-exec` execs the command in place, so the child keeps its pid, process group, and exit code. It gets the path Go already resolved, so the sandbox never changes which binary runs, and a failed lookup still fails in `Start`.
  - The profile matches real paths, so both folders go through `filepath.Abs` and `filepath.EvalSymlinks`. A home not created yet resolves through its parent; an unset home, a missing parent, or a dangling symlink is a denial.
  - `CheckPolicy` builds the prefix (rule 16): no `sandbox-exec` (any host but macOS), one that cannot be read, or a folder that does not resolve is a denial before any vault opens. The reason keeps only the error's cause, never a path (rule 36). `ExecBlind` runs the exact prefix the check built, so nothing new can fail after the mint.
  - The audit entry and every error keep the command as the request gave it: the profile and the paths never reach the audit log or an agent.
  - `SandboxExecPath` is a var, so unit tests run a stub (rule 22).
- **Spike (2026-10-16 and 2026-10-17, macOS 27.0 build 26A428, a throwaway `HOME`; no real vault or Keychain item was read):**
  - `pass` The home rule alone: reading `vault.json`, listing the directory, and writing into it fail (exit 1, `Operation not permitted`); other `HOME` files, a local HTTP request (200), and `git` still work.
  - `pass` The whole profile: `security find-generic-password` can no longer start a search. It exits 44 like a miss, but `stderr` says `One or more parameters passed to a function were not valid` instead of `could not be found`.
  - `pass` The whole profile: a Go program through the platform verifier, `curl`, `git` over HTTPS, and `python3` `urllib` still reach HTTPS servers, and `curl` still refuses a self-signed certificate.
  - `pass` The Keychain file rule without the `mach-lookup` names changed nothing a probe could see, so those names are required.
  - `pass` `sandbox-exec` execs in place (same pid); a missing command exits 71 and a bad profile 65. Paths match case-insensitively. Inside the sandbox, linking a file of a denied folder (symlink or hard link) and reading through a symlink are denied; a hard link made before the command ran stays readable.
  - `pass` The child could not read its parent's environment: `ps -E -ww -p $PPID` and `sysctl KERN_PROCARGS2` on the parent returned 319 to 742 bytes without the canary, while the same reads of the child's own pid returned 5,012 bytes with it (the positive control). README §5 and rule 23 say this for macOS 27.0 only.
  - Not tested: `launchctl submit`, or any other request that has a process outside the sandbox run something.
- **Cost:** inside the sandbox, a tool that keeps its own credential in the Keychain (`gh` with a stored token, `git` with `osxkeychain`) fails; the lease's environment (`GH_TOKEN`, `CLOUDFLARE_API_TOKEN`, …) replaces it.
- **Not built:** Linux (§3 item 1 keeps the design; `sandbox` is a denial there); `no_network`; `init policy` does not suggest `sandbox`. The approval text and the audit entry came later (Workstream Z).
- **Deliverables:**
  1. `[SERIAL]` core: the fields, the profile, `SandboxExecPath`, `CheckPolicy`, and `ExecBlind`. `TestExecBlindSandbox`: a stub `sandbox-exec` logs its exact argv for policy only, request only, and policy on with the request off, and is never called when neither is on; a symlinked home, a relative home, and a home not created yet resolve. `TestCheckPolicyMatchesExecBlind`: no `sandbox-exec`, a missing one, no Keychain folder, an unset home, a home whose parent is missing, and a dangling symlink are denied by both, with no path in the reason.
  2. `[SERIAL]` MCP `sandbox` in both tools' schema (`TestMCPExecSchema`) and the CLI's `-sandbox` (`TestCLIExecSandbox`).
  3. `[SERIAL]` `-tags integration` tests against the real `sandbox-exec`, each denial with a positive control (the same read without the sandbox; for listing and writing, a listing of `mintrun`'s home without it and a write outside both folders with it): `TestSandboxHidesHome` (a canary file in a throwaway home) and `TestSandboxHidesKeychainItem` (a throwaway login Keychain item, run only after the user's go-ahead).
  4. `[SERIAL]` Mutants on a copy of the repo, each failing a test, and the hermetic proof with a logging stub `sandbox-exec` (rule 22).
  5. `[SERIAL]` README, AGENTS.md rule 43 (and `sandbox-exec` in rule 22), `checks.md`, `progress.md`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestExecBlindSandbox' ./internal/core
  go test -count=1 -v -run 'TestMCPExecSchema' ./internal/builtin
  go test -count=1 -v -run 'TestCLIExecSandbox' ./cmd/mintrun
  go test -count=1 -v -tags integration -run '^TestSandboxHidesHome$' ./internal/core
  # Only after the user's go-ahead: it stores and deletes a throwaway login Keychain item.
  go test -count=1 -v -tags integration -run '^TestSandboxHidesKeychainItem$' ./internal/core
  ```

### Workstream Z — The Approval Text and the Audit Log Say Whether the Sandbox Is On
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/telegram_test.go`, `internal/builtin/slack_test.go`, `internal/builtin/builtin_test.go`, `README.md`, `AGENTS.md`, `plan.md`, `checks.md`, `progress.md`
- **Gap:** Workstream Y left both out. An approver saw the provider, the command, and the working directory but not whether the command would run in the sandbox, and neither `audit.jsonl` nor `mintrun_audit` told a sandboxed run from an unsandboxed one.
- **Design:**
  - `AuditEntry.Sandbox` (`json:"sandbox,omitempty"`). `checkPolicy` sets it from the verdict it hands the approver, before asking, and from the verdict it enforces. A request the gate blocks before asking has none, since no verdict allowed it (`PolicyDecision.Sandbox` is false on every denial, a `blocked_by: sandbox` one included). A request the gate blocks after an approval keeps what the human was shown. Every later exit (vault, provider, mint, command) keeps the enforced value. `mintrun_audit` copies booleans as they are, so it shows the field with no code change.
  - `ApprovalText` adds `Sandbox: on` or `Sandbox: off` as the first line after the header. `mintrun` writes it, so it is not quoted, and it comes before every field an agent sets (provider, vault, scope, permissions, params, command), so no long field can push it behind the TRUNCATED warning. The approver gets the first verdict's sandbox (policy or request), and the second verdict can only add it (rule 43), so `on` is a promise and `off` means no sandbox unless a rule saved while the human decides turns it on.
- **Deliverables:**
  1. `[SERIAL]` core: the field, `checkPolicy`, and the line. `TestExecBlindSandbox` pins the field for every case (neither, request, policy, the symlinked, relative, and new homes, a sandbox dropped or added during approval), what the approver is shown, a denied approval, a block after an approval, and the raw `"sandbox":true` key; `TestCheckPolicyMatchesExecBlind` pins none on a `blocked_by: sandbox` entry. `TestOSApproval` pins `on` in the dialog literal and `off` for an empty request.
  2. `[SERIAL]` `TestTelegramApproval` and `TestSlackApproval` pin the new line in their exact text; `TestMCPBridgeGovernanceTools` pins that `mintrun_audit` shows a seeded entry's `"sandbox":true` and none on the blocked one.
  3. `[SERIAL]` Mutants on a copy of the repo (the new ones and rule 4's 13), each failing a test; the hermetic proof with logging stubs (rule 22).
  4. `[SERIAL]` README, AGENTS.md rules 4, 16, 31, 34, and 43, `checks.md`, `progress.md`.
- **Not built here:** `AppApproval` sends the app the request's fields, not `ApprovalText`, so `appRequest` gained the sandbox separately (App Socket Sends the Sandbox, below).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestExecBlindSandbox|TestOSApproval' ./internal/core
  go test -count=1 -v -run 'TestTelegramApproval|TestSlackApproval|TestMCPBridgeGovernanceTools' ./internal/builtin
  ```

### App Socket Sends the Sandbox
- **Files:** `internal/builtin/appbroker.go`, `internal/builtin/appbroker_test.go`, `AGENTS.md`, `plan.md`, `checks.md`, `progress.md`
- **Gap:** Workstream Z put `Sandbox: on` or `off` in `ApprovalText`, which the dialog, Telegram, and Slack show. `AppApproval` sends the app the request's fields instead, and `appRequest` had no sandbox, so the macOS app could not show it.
- **Design:**
  - `appRequest.Sandbox` (`json:"sandbox"`), filled from `req.Sandbox`, which `checkPolicy` sets to the verdict before it asks, so the app gets what the other channels show. It is sent when false too, so the app can tell a run without the sandbox from an older mintrun that sends no key.
  - `AppTrack`'s started line is an `AuditEntry`, whose `sandbox` stays `omitempty` (Workstream Z), so the app reads a missing key there as off. No change.
- **Deliverables:**
  1. `[SERIAL]` The field, and the comment above `appRequest` that says it is mintrun's verdict.
  2. `[SERIAL]` `TestAppApproval` compares the exact request line with the sandbox off (`Approve`, `CleanEnv`, and `FromAgent` on) and on (those three off), so a field taken from another flag fails.
  3. `[SERIAL]` Mutants on a copy, each built first and each failing the test; the pipeline and the hermetic proof in a `git archive` export; AGENTS.md rule 42, `checks.md`, `progress.md`. README never describes the app socket, so it does not change.
- **Not built:** the macOS app is not in this repo, and it must show the field (`progress.md`). Nothing in `cmd/mintrun` called `AppApproval` then; X7 wires it in (Workstream X, Phase 3).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestAppApproval|TestAppTrack' ./internal/builtin
  ```

### Workstream AA — Sandbox the Blind Command on Linux
- **Files:** `internal/core/runner.go`, `internal/core/sandbox_linux.go`, `internal/core/sandbox_other.go`, `internal/core/core_test.go`, `internal/core/sandbox_linux_test.go`, `internal/core/sandbox_integration_test.go`, `cmd/mintrun/main_test.go`, `README.md`, `AGENTS.md`, `plan.md`, `checks.md`, `progress.md`
- **Gap:** Workstream Y built the child sandbox on macOS only (`sandbox-exec`); on Linux, a sandboxed request was denied (`blocked_by: sandbox`).
- **Design:**
  - `LinuxSandboxPath` defaults to `os.Executable()` on Linux when `/usr/bin/sandbox-exec` is absent. When `os.Args[1] == "-mintrun-linux-sandbox"`, `init()` in `internal/core/sandbox_linux.go` calls `runLinuxSandbox` before `main`.
  - `linuxSandboxArgv(homeDir)` resolves `mintrun`'s home (`realDir`), resolves existing keyring directories (`~/.local/share/keyrings`, `$XDG_DATA_HOME/keyrings`, `/run/user/<uid>/keyring` via `LinuxRunDir`, `$XDG_RUNTIME_DIR/keyring`, rejecting relative `XDG_DATA_HOME`/`XDG_RUNTIME_DIR`) and D-Bus session bus sockets (`/run/user/<uid>/bus`, `$XDG_RUNTIME_DIR/bus`, and a single absolute `unix:path=<sock>` in `DBUS_SESSION_BUS_ADDRESS`, rejecting `unix:abstract=...`, `tcp:...`, `;`, `%`, or a relative path), collapses subpaths (`subpath(d, real)` and `subpath(real, d)`) and duplicate sockets, and executes a dry-run probe (`LinuxSandboxPath -mintrun-linux-sandbox -hide-dir ... -hide-file ... --` with `LinuxSandboxSysProcAttr`) during `decide` (`CheckPolicy` / `checkPolicy`) so any host that blocks unprivileged user or mount namespaces (`user.max_user_namespaces=0`, AppArmor userns restriction) fails closed before any vault opens, with zero local paths in the denial reason (`pathCause`, rule 36).
  - `ExecBlind` creates `sandbox[3]` (`_ = os.MkdirAll(sandbox[3], 0o700)`) and calls `LinuxSandboxSysProcAttr(cmd)` (`CLONE_NEWUSER | CLONE_NEWNS`, 1-to-1 UID/GID maps, `GidMappingsEnableSetgroups: false`, `AmbientCaps: []uintptr{capSysAdmin, capSetpcap}`) when running behind `-mintrun-linux-sandbox`.
  - In the helper, `setupLinuxSandbox` mounts a `size=4k,mode=000` `tmpfs` (`MS_NOSUID|MS_NODEV|MS_NOEXEC`) and remounts it `MS_REMOUNT|MS_RDONLY` over each `-hide-dir` (or `filepath.Dir(dirs[0])` during a `CheckPolicy` dry-run probe when `dirs[0]` does not exist yet on disk, preserving rule 16), bind-mounts `/dev/null` over each `-hide-file`, locks `PR_SET_SECUREBITS` to `0x2f` (`secbitsLockedNoRoot`), zeroes `Effective`, `Permitted`, and `Inheritable` via `SYS_CAPSET` (which also clears `Ambient` in the kernel), and when `len(cmd) > 0` calls `syscall.Chdir(cwd)` (after capabilities are dropped, so even `uid == 0` fails with `permission denied` if `cwd` is inside a hidden directory) and `syscall.Exec`s `cmd` in place (same pid and process group).
  - `/proc/$PPID/environ` is unreadable inside the user namespace without `PR_SET_DUMPABLE` because `mintrun` is outside the child's user namespace and the child has zero capabilities (`Permission denied`, pinned in `TestSandboxHidesHome`).
- **Deliverables:**
  1. `[SERIAL]` core: `LinuxSandboxPath`, `LinuxRunDir`, `LinuxSandboxSysProcAttr`, `linuxSandboxArgv`, `runLinuxSandbox`, `setupLinuxSandbox`, and `ExecBlind` wiring. `TestExecBlindLinuxSandbox`, 28 Linux denial cases in `TestCheckPolicyMatchesExecBlind/sandbox`, `TestCLIExecSandbox`, and `TestLinuxSandboxSysProcAttrAndHelper` (`//go:build linux`, run both as unprivileged user and as `root`).
  2. `[SERIAL]` `-tags integration` tests on Linux (`Ubuntu 24.04.5 LTS`, kernel `6.17.8`): `TestSandboxHidesHome` (including `/proc/$PPID/environ` and running as `root`) and `TestSandboxHidesSecretTool` (real `dbus-daemon`, `gnome-keyring-daemon`, and `/usr/bin/secret-tool`).
  3. `[SERIAL]` 38 Linux sandbox mutants on a copy (26 in `runner.go` and 12 in `sandbox_linux.go`), each failing a test, and the hermetic proof with logging stubs on both macOS and Linux (rule 22).
  4. `[SERIAL]` README, AGENTS.md rules 22 and 43, `checks.md`, `progress.md`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestExecBlindSandbox|TestExecBlindLinuxSandbox|TestLinuxSandboxSysProcAttrAndHelper' ./internal/core
  go test -count=1 -v -run 'TestCLIExecSandbox' ./cmd/mintrun
  go test -count=1 -v -tags integration -run '^TestSandboxHidesHome$' ./internal/core
  go test -count=1 -v -tags integration -run '^TestSandboxHidesSecretTool$' ./internal/core
  ```

---

## 3. Deferred Backlog (Next Actionable Items)

1. **`no_network` Child Sandbox Option (completed in `v0.12.0`, Workstream AC, rule 46):** `"no_network": true` in `policy.json`, CLI `-no-network`, and MCP `no_network: true` imply `sandbox: true` and block network egress inside the child (`(deny network*)` on macOS; `CLONE_NEWNET` + 9-instruction `seccomp-bpf` filter on `linux/amd64` and `linux/arm64`). Verified via `TestSandboxBlocksNetwork` on macOS 27.0 and Ubuntu 24.04 (`linux/arm64`, kernel 6.17); `linux/amd64` live integration run awaits an x86-64 Linux host.
2. **Linux Host Verification:** moved to the §5 live-check runbook, item 4 (`-approve` with Telegram and Slack as the only channels; `secret-tool` is already verified).
3. **Live Runs: Telegram, 1Password, Bitwarden & Vercel:** moved to the §5 live-check runbook, items 2–3 (each run with the user's own throwaway bot or account; `checks.md` §3 turns `pass` only on that run's output).
4. **Live Slack Approval Run:** moved to the §5 live-check runbook, item 2 (the user's own throwaway workspace and app).
5. **GCP `token_uri` From the Service-Account Key:**
   - Deferred: only keys outside the default Google universe carry a different `token_uri`, and honoring it also means sending revocation to that universe. Add it when such a key is in use.
6. **Team Relay (`mintrun relay`, completed in `v0.13.0`, Workstream AE, rule 47):** TLS 1.3 SPKI-pinned relay server (`mintrun relay serve`), SHA-256 device token auth (`mintrun relay device add|remove|list`), client (`exec -relay`, `MINTRUN_RELAY`, `MINTRUN_RELAY_TOKEN`), and MCP support; see [§5](#5-roadmap-to-v0120--v0130-approved-2026-10-18) and [checks.md](checks.md).

---

## 4. Workstream X — macOS App Hooks (approved 2026-10-17)

> The Go side of the private design canvas for the mintrun macOS app. Approved on 2026-10-17, with the open questions answered by their recommended defaults (below); Phase 1 is built first. It was planned as Workstream N while Workstream M (onboarding: `mintrun init` and `mintrun doctor`) was in progress in another checkout; `main` gave N and every letter through W to other work, so this is Workstream X, with steps X0–X8.

| Hook | Steps |
| :--- | :--- |
| 1. In-app approval broker that races the dialog, Telegram, and Slack, with a timeout that denies | X1a, X1b, X1c, X7 |
| 2. Global pause | X2 |
| 3. Client identity in `audit.jsonl` and `mintrun_audit` | X0, X3 |
| 4. Stopping a running task, which is still revoked and audited | X4, X1b (`AppTrack`), X7 |
| 5. Plain-language purpose in `mintrun_exec` and the approval prompt | X0, X5, X3 (schema) |
| 6. Installer for the Claude Code, Claude Desktop, and Cursor configs | X6 |
| 7. Settings: key store and notifications | X7 |
| Reload `policy.json` on every request (approved with question 5) | X8 |

- **Order:**
  - Phase 1: `[SERIAL]` X0 → X2 → X5 → X1a → X4 → X8, all in `internal/core/runner.go` and `internal/core/core_test.go`. Built on 2026-10-17; the evidence is in [checks.md](checks.md) (Workstream X, Phase 1).
  - Phase 2: `[PARALLEL]` X1b and X3, which need Phase 1's fields. Their files are disjoint but compile as one package, so each runs in its own worktree and they merge one at a time, with `go test -count=1 ./internal/builtin` after each merge. Built on 2026-10-17, with X3b (agent-written text kept out of `mintrun_audit`) and the fork-race fix (rule 20), and brought up to date with `main` through its shim profile fix; the evidence is in [checks.md](checks.md) (Workstream X, Phase 2).
  - Phase 3, now that Workstream M has landed (it edits `cmd/mintrun/main.go`, `README.md`, and `internal/builtin/telegram.go` and `slack.go` with their tests, and exports what X6 reuses): `[PARALLEL]` X1c alongside `[SERIAL]` X6 → X7; then the docs and the full §1 pipeline. Built on 2026-10-17 in one worktree, X1c first; the evidence is in [checks.md](checks.md) (Workstream X, Phase 3). `appRequest` carries the sandbox since App Socket Sends the Sandbox (section 2); the macOS app must show it.
- Every check runs with `-v`, and each new test must show `--- PASS` (rule 15). On 2026-10-17, `go test -list` showed each check's regex selecting the existing tests it names, and none of the new test names exists yet.
- **Merging Phase 1:** merge X3 first or together with it, because until X3, `mintrun_audit` hands agents the `purpose` an agent wrote. Workstream M's `cmd/mintrun/setup.go` reads `Runtime.Policies`, which X8 removed: in `policy()`, replace `if _, ok := w.rt.Policies["github"]; ok {` with `rules, _ := w.rt.LoadPolicies()` and `if _, ok := rules["github"]; ok {` (verified on a trial merge). `doctorPolicy` should call `rt.LoadPolicies()` too: after X8 its FAIL text (`exec then allows every request`) is wrong, since a file that fails to load now denies every exec.

### X0 — Activity Record
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`
- **Deliverables:**
  1. `[SERIAL]` `ExecRequest` gains `Purpose` (`json:"purpose,omitempty"`) and `Client`, `Via`, `Task` (`json:"-"`: MCP arguments unmarshal straight into `ExecRequest`, so an agent cannot set them).
  2. `[SERIAL]` `ExecBlind` gives each call a `Task` (`rand.Text()`, an opaque handle; rule 7) and builds one base entry up front (`ts`, `task`, `provider`, `scope`, `permissions`, `command`, `purpose`, `client`, `via`) that every exit path completes, so the policy-denial entry gains `permissions`. The three exits that write no entry today (unknown vault, unknown provider, a master the vault cannot load) are audited as `failed`, exit 1. Tests that count entries change.
  3. `[SERIAL]` `AuditEntry` gains `task`, `via`, `client`, `purpose`, `outcome`, `blocked_by`, `decided_at` (when a human answered), and `expires_at` (ephemeral leases only, because a static lease is the master secret, whose expiry `mintrun` does not know). Every entry written after the master is loaded scrubs `client` and `purpose` like `command` (rule 8).
  4. `[SERIAL]` `outcome`:
     - `blocked`: `CheckPolicy` denied. `blocked_by` names why: `invalid_request`, `paused`, `purpose`, `policy_file`, `env_dump`, `static`, `scope`, `permission`, `installation`, `command`. `PolicyDecision` gains the same `blocked_by`, so `mintrun_policy_check` reports it.
     - Approval: `denied` (a human said no), `no_answer` (the approval deadline passed), `failed` (every channel failed first), `interrupted` (the caller's context ended), and `blocked` when the re-check after an allow denies (X2).
     - `failed`: the vault, provider, or mint failed, or the command could not start or exited non-zero.
     - Run: a clean exit (exit 0, or `exec.ErrWaitDelay` after one) is `done`, even if a stop raced it. Otherwise, in order: `stopped` (X4), `interrupted` (a signal to `mintrun` or the MCP server shutting down; never shown as "you stopped it"), `timed_out` (the exec timeout), `failed`.
  5. Older entries have no `outcome`; the app shows them by exit code.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestAuditActivityFields|TestCheckPolicyMatchesExecBlind|TestExecBlindCleanEnv|TestExecBlindOutputCap' ./internal/core
  ```

### X2 — Global Pause
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`
- **Deliverables:**
  1. `[SERIAL]` While `<home>/paused` exists, `CheckPolicy` denies every request (`blocked_by: paused`, reason `policy denied: mintrun is paused`) right after the empty-command and empty-provider checks. `os.Lstat` decides: any entry, a dangling symlink included, means paused, and so does any error other than not-exist (fail closed). `ExecBlind`, `mintrun_policy_check` (rule 16), and the CLI all stop. The reason never says how to resume, because an agent with a shell could.
  2. `[SERIAL]` After an approval allows, `checkPolicy` runs `CheckPolicy` again and uses that decision, so a pause (and, with X8, a rule change) made while the request waited still applies.
  3. No CLI subcommand: the app creates and removes the file, and a terminal user can `touch` or `rm` it.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestPauseRecheckAfterApproval' ./internal/core
  ```

### X5 — Plain-Language Purpose
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`
- **Deliverables:**
  1. `[SERIAL]` After the pause check, `CheckPolicy` denies (`blocked_by: purpose`) a purpose over 300 bytes, not valid UTF-8, or holding a Unicode `Cc`, `Cf`, `Zl`, or `Zp` character (newlines, bidi controls, zero-width characters). An empty purpose is fine. No rule reads it and the CLI has no flag for it: it is the agent's claim, never trusted.
  2. `[SERIAL]` `core.ApprovalText` adds quoted `Purpose:` and `Client:` lines after `Command:`, its last line today, only when they are set. The dialog, Telegram, and Slack all show them with no other change; a long request is cut through these claims before any fact; and the existing approval tests keep their text.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestPurposeValidation|TestOSApproval|TestCheckPolicyMatchesExecBlind' ./internal/core
  ```

### X1a — Approval Timeout
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`
- **Deliverables:**
  1. `[SERIAL]` `Runtime.ApprovalTimeout` (0, or more than 10 minutes, means 10 minutes; question 9) bounds the approval through `context.WithTimeout`. The deadline kills the `osascript` dialog (`exec.CommandContext`), ends the Telegram and Slack polls (both return when their context ends), and closes the app's connection (X1b). The reason is `policy denied: no answer within <timeout>`, and the outcome is `no_answer`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestApprovalTimeout|TestFirstApproval|TestOSApproval' ./internal/core
  ```
  `TestApprovalTimeout`: a stub `osascript` that sleeps is killed at a short deadline (`no_answer`), and a caller context cancelled first gives `interrupted`.

### X4 — Stopping a Running Task
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`
- **Deliverables:**
  1. `[SERIAL]` `Runtime.Track func(ctx context.Context, started AuditEntry) <-chan struct{}` (nil: no tracking) runs after `Mint` and before the command starts. `started` holds the base fields (`command` scrubbed) plus the scrubbed lease ID, `ephemeral`, and `expires_at`. Its `ctx` comes from `context.WithoutCancel` and ends right after the final entry is written, so the app sees a task end only once its outcome is in the log.
  2. `[SERIAL]` Closing the returned channel cancels the run through `context.WithCancelCause` with `errStopped`, and the exec timeout derives from that context. On Unix the whole process group is killed (rule 20). Revoke and audit run as on any exit. A stop before the command starts makes `Start` fail, and the task is still revoked and recorded as `stopped`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestExecBlindStop|TestExecBlindTrackEndsAfterAudit|TestExecBlindKillsProcessGroup' ./internal/core
  ```
  `TestExecBlindStop`: a stopped `sleep 60` returns in under 5 s, its process group is gone, revoke ran, and the entry says `stopped`. Its `TimeoutSec: 1` case says `timed_out`, and a cancelled caller context says `interrupted`.

### X8 — Policy Reload (approved; changes behavior)
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`
- **Deliverables:**
  1. `[SERIAL]` `CheckPolicy` reads `policy.json` on every call. A missing file means no rules, as at boot today. A malformed or unreadable one denies everything (`blocked_by: policy_file`); today an unreadable file is skipped at boot, as if there were no rules. `Runtime.Policies` and `policyErr` go away, and the boot warning stays. Only `runner.go` used them on this branch, but Workstream M's `cmd/mintrun/setup.go` reads `Runtime.Policies`, so merging needs the fix in **Merging Phase 1** above.
  2. `[SERIAL]` As built: `decide` (the body of `CheckPolicy`) returns the checked rule's `allowed_env` beside the decision, and `ExecBlind` passes it to `childEnv`, so `ExecBlind` enforces the rule it checked instead of reading the policy again. A slice field on `PolicyDecision` would make it incomparable, and the `builtin` tests compare decisions with `!=`. `LoadPolicies` is exported for the app; a directory or a dangling symlink at `policy.json` denies like a malformed file, and the reason leaves out the path.
  3. Why: each AI app keeps its own `mintrun mcp` running, so without a reload a rule saved in the app's Rules screen waits until that app restarts it.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestPolicyReload|TestPolicyFailClosedPhase45PRB|TestCheckPolicyMatchesExecBlind' ./internal/core
  ```

### X1b — In-App Approval Broker and Task Tracking
- **Files:** `internal/builtin/appbroker.go`, `internal/builtin/appbroker_test.go` (new)
- **Deliverables:**
  1. `[PARALLEL]` The macOS app listens on `<home>/app.sock` (mode 0600, inside the 0700 home), and `mintrun` dials it: one connection per approval and one per running task, newline-delimited JSON with `"v":1`.
  2. `[PARALLEL]` `AppApproval(rt, fallback)`: when the dial fails it calls `fallback` (`OSApproval`), so a running app replaces the dialog while Telegram and Slack still race. It sends `{"v":1,"type":"approve","task":…,"request":{sandbox,provider,scope,permissions,params,command,cwd,purpose,client,via,ttl_seconds}}` (`sandbox` came later, in App Socket Sends the Sandbox) and reads one line of at most 4 KiB: `{"task":…,"decision":"allow"|"deny"}`. A wrong task, a malformed or oversized line, or EOF is an error, never an approval, and no dialog follows. When `ctx` ends it closes the connection, and the app drops the card. The command is sent whole, so the app must say when it shortens it.
  3. `[PARALLEL]` `AppTrack(rt)` returns a `Runtime.Track`. It dials with a 1 s timeout and a write deadline, and a failure means no tracking. It sends `{"v":1,"type":"started","entry":…}`, closes the stop channel on a `{"type":"stop"}` line, and closes the connection when `ctx` ends. A connection that closes with no audit entry for its task means `mintrun` died, and the app says so rather than guess.
  4. `[PARALLEL]` Trust matches `policy.json`'s: there is no owner or peer check, because a same-user process can already edit the home (rule 23) and the check would need per-OS `syscall` code. No build tags: where no app listens, the dial fails.
  5. Tests serve the socket from a short `os.MkdirTemp("", "mr")` directory, because macOS limits a socket path to 104 bytes; a longer `MINTRUN_HOME` just means no app channel.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestAppApproval|TestAppTrack' ./internal/builtin
  ```

### X3 — Client Identity Over MCP
- **Files:** `internal/builtin/mcp.go`, `internal/builtin/builtin_test.go`
- **Deliverables:**
  1. `[PARALLEL]` `Serve` keeps `initialize`'s `params.clientInfo.name` in a local variable (one `MCPBridge` value serves every `Serve` call), keeps only `[A-Za-z0-9._ ()-]` characters, cuts it to 64 bytes, and sets `Client` and `Via: "mcp"` on each `mintrun_exec`. An empty result records no client, and a `client` in an agent's arguments is ignored (`json:"-"`). The name is self-reported.
  2. `[PARALLEL]` `execSchema` gains `purpose`. `mintrun_audit` returns the new fields, `task`, `client`, `via`, `outcome`, and `blocked_by` among them, but never `purpose`, which `readAudit` blanks because one agent could use it to slip text to another.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestMCPBridgeClientInfo|TestMCPBridgeGovernanceTools|TestMCPBridgeComprehensive' ./internal/builtin
  ```

### X1c — Deadline Text in Telegram and Slack
- **Files:** `internal/builtin/telegram.go`, `internal/builtin/slack.go`, `internal/builtin/telegram_test.go`, `internal/builtin/slack_test.go`
- **Deliverables:**
  1. `[PARALLEL]` Today, when the context ends first, both return `ctx.Err()` and leave the edited message at `⌛ Closed: answered on another channel, or canceled.`; only their own 10-minute timer sets `⌛ Expired: …`. When `ctx.Err()` is `context.DeadlineExceeded` (the approval deadline of X1a), the message says `⌛ Expired: no answer in time, so not approved.` instead, so the phone never claims that another channel answered.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestTelegramApproval|TestSlackApproval' ./internal/builtin
  ```

### X6 — App Config Installer
- **Files:** `cmd/mintrun/apps.go`, `cmd/mintrun/apps_test.go` (new), `cmd/mintrun/main.go`
- **Deliverables:**
  1. `[SERIAL]` `mintrun apps status|connect|disconnect [-app claude-code,claude-desktop,cursor] [-dry-run] [-command <abs path>]`, non-interactive with JSON output, for the macOS app. A dry run writes nothing and reports `{app, config, change: add|update|remove|none, old, new}` per app; status reports `{app, found, config, installed, matches}`, where `matches` compares `command` and `args`.
  2. `[SERIAL]` The entry is `{"command":<path>,"args":["mcp"]}`, with no `env` and no `type`. The path follows Workstream M's rule (`os.Executable` plus `EvalSymlinks`, a `go run` build refused) unless `-command` names an absolute path to an executable file.
  3. `[SERIAL]` Claude Code goes through its own CLI, as Workstream M's `init mcp` does, found with `exec.LookPath` (`err == nil` only; rule 14). The macOS app passes its login shell's `PATH`, because an app started from the Dock lacks `~/.local/bin`. Status reads the user-scope `mcpServers.mintrun` in `~/.claude.json` and never writes it. Connect runs `claude mcp add -s user mintrun -- <path> mcp`, after `claude mcp remove -s user mintrun` when a stale entry exists. A stale entry that holds anything besides `type`, `command`, `args`, and an empty `env` is refused with an error naming those keys, never their values: the CLI would need them on argv (rule 14), and dropping them is an edit nobody asked for. Disconnect runs `claude mcp remove -s user mintrun` when an entry exists.
  4. `[SERIAL]` Claude Desktop (`<os.UserConfigDir()>/Claude/claude_desktop_config.json`, created only when its `Claude` directory exists) and Cursor (`~/.cursor/mcp.json`, created only when `~/.cursor/` exists) get a byte-level splice, so nothing else in the file changes. It checks `json.Valid`, then finds spans with `json.Decoder` tokens and `InputOffset`. It refuses a root, `mcpServers`, or `mintrun` value that is not an object, and a duplicate `mcpServers` or `mintrun` key. A new entry goes in right after the `{` of `mcpServers`, as its first member, with the old first member's leading whitespace (a newline and the `mcpServers` line's indentation plus two spaces when there is none). A missing `mcpServers` is added, and disconnect then leaves it empty. Connect sets `command` and `args` and keeps every other key in the entry, such as a user's `env`; an entry that already matches is not rewritten. Disconnect removes the member, its leading whitespace, and one comma next to it. When `mcpServers` already held another server, connect then disconnect restores the original bytes.
  5. `[SERIAL]` A write resolves the target with `filepath.EvalSymlinks`, reads it again and stops if it changed since the first read, then writes through M's `builtin.WriteFileAtomic` (temp file in the same directory, `Sync`, `os.Rename`), keeping the file's mode (0600 for a new file).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIApps' ./cmd/mintrun
  ```
  The tests run in `setupEnv`'s fake `HOME`: `HOME` and `PATH` (a stub `claude` that logs its argv) are temporary directories, and `XDG_CONFIG_HOME` is cleared, so every config path falls under that `HOME`. Most pass `-command`; `os.Executable` is stubbed for the default command and the `go run` refusal.

### X7 — Settings and Wiring
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`
- **Deliverables:**
  1. `[SERIAL]` `bootRuntime` reads `<home>/settings.json` (`{"vault":"keychain"|"1password"|"file","approval_timeout_seconds":1..600}`) before it registers the vaults. `file` sets `ForceFile: true` and an empty `SecretTool` on the vault `NewKeychainVault` returns. A non-empty `MINTRUN_VAULT` or `MINTRUN_FILE_VAULT=1` wins over the file's `vault`. Unknown keys are ignored; malformed JSON or a bad known value stops boot with an error. The file is read only at boot. The timeout tops out at 600 s because Telegram and Slack stop at their own 10 minutes.
  2. `[SERIAL]` Wiring: `rt.ApprovalFunc = core.FirstApproval(builtin.AppApproval(rt, core.OSApproval), builtin.TelegramApproval(rt), builtin.SlackApproval(rt))`, `rt.Track = builtin.AppTrack(rt)`, `rt.ApprovalTimeout` from the settings, and `Via: "cli"` on CLI requests.
  3. Notifications need no Go code: the app watches `outcome` in `audit.jsonl` and its own approval connections, and keeps the on/off switch in its own preferences.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestBootRuntimeSettings|TestCLIExecPaused|TestCLISubcommandsEndToEnd' ./cmd/mintrun
  ```

### Coverage Gate and Hermeticity
- Total coverage stays above 90%; it was 94.1% in this tree before Workstream X and 94.5% after Phase 1 (rule 5). The new files must appear in the profile, and none of their functions may sit at 0.0%:
  ```bash
  go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -n 1
  go tool cover -func=coverage.out | grep -c -E '/(appbroker|apps)\.go:'   # > 0 (positive control)
  go tool cover -func=coverage.out | grep -E '/(appbroker|apps)\.go:' | grep -c -E '[[:space:]]0\.0%$'   # must print 0
  printf 'm/apps.go:1:\tf\t0.0%%\n' | grep -E '/(appbroker|apps)\.go:' | grep -c -E '[[:space:]]0\.0%$'   # must print 1 (planted control)
  rm -f coverage.out
  ```
- The installer tests set `HOME` and `PATH` to temporary directories and clear `XDG_CONFIG_HOME` (rule 22). To prove it, run the suite with an empty `HOME` and check that no file appears in it outside Go's own caches, then plant a write with the rebuilt binary as the positive control. On 2026-10-17 the first line printed nothing on this tree, and a planted `.cursor/mcp.json` printed:
  ```bash
  S="$(mktemp -d)"; GOCACHE="$(go env GOCACHE)" GOMODCACHE="$(go env GOMODCACHE)" GOPATH="$(go env GOPATH)" HOME="$S" go test -count=1 ./... && find "$S" -type f -not -path "$S/Library/Caches/*" -not -path "$S/Library/Application Support/go/*"   # must print nothing
  mkdir "$S/.cursor" && HOME="$S" ./mintrun apps connect -app cursor && find "$S" -type f -not -path "$S/Library/Caches/*" -not -path "$S/Library/Application Support/go/*"   # must list .cursor/mcp.json
  ```

### Live Checks (`unresolved` until the user runs them)
- **L1:** which `clientInfo` names Claude Code, Claude Desktop, and Cursor send. An agent's `mintrun_exec` with an empty command is audited as `blocked` with its client and needs no stored secret.
- **L2:** `mintrun apps connect` for each real app: each starts `mintrun mcp` and lists its tools, `mintrun apps status` reports each as installed and matching, and `disconnect` removes only the `mintrun` entry (the Claude Desktop and Cursor files compared byte for byte with copies taken before connect).
- **L3:** the macOS app end to end: allow, deny, no answer, stop, and pause.
- **L4:** the real macOS dialog closes at the approval deadline.

### What the Docs Must Say (rules 21 and 23)
- Pause blocks new requests only: running tasks and credentials already handed out keep working.
- An agent with its own shell can get around pause and the rules: run `security` itself, point `MINTRUN_HOME` elsewhere (no `policy.json` or pause file there, while the Keychain items stay readable), or delete the pause file.
- Stop kills the command's process group on Unix (only the process elsewhere), and a daemon that left the group survives. On stop, as on any exit, `cloudflare` and `github` JIT tokens are deleted; `aws` and `gcp` credentials keep working until they expire (rules 13 and 21); a plugin's lease ends early only when its own revoke succeeds, which the entry's `revoked` reports; and a static lease is the master secret itself, never revoked.
- Approval does not stop code already running as the user, which can answer on the socket, edit `policy.json`, or delete the pause file.
- Client names are self-reported, and the purpose is the agent's claim: the app labels both so.
- The macOS dialog now closes at the approval deadline instead of waiting forever, so the README approval section and rule 31 change.

### Docs and Rules (Phase 3)
- README: approval (the app channel, the timeout), the MCP tools table (`purpose`, the new audit fields), pause, stop, `mintrun apps`, `settings.json`, and the points above.
- AGENTS.md: Phase 1 amended rules 4 (the `Purpose` and `Client` lines), 8 (one entry per exit), 16 (pause, purpose, and the policy reload in `CheckPolicy`), 20 (the `Track` stop), 22 (mutants must compile; stubs `exec` their helper), and 31 (the deadline). Phase 3 adds the app channel to rule 31 and the Expired text to rule 34, and new rules 44 (`mintrun apps`) and 45 (`settings.json` and the wiring), after rule 43, written from what the tests pinned.
- `checks.md`: one row per hook and per live check. `progress.md`: a checkpoint.

### Open Questions (decided 2026-10-17: the recommended defaults)
1. Which `clientInfo` names do the three apps send? L1 answers it; until then `mintrun` records whatever arrives. **Decided:** record whatever arrives.
2. X6 builds on Workstream M. Agree with M's owner that M's Claude Desktop writer uses X6's splice, so neither rewrites the rest of the file; that `apps connect` updates a stale entry while `init mcp` leaves one alone; that `apps` writes `~/.cursor/mcp.json`, because a dry run and status need a file, while `init mcp` opens Cursor's link; and how the app passes `PATH`. If M is dropped, X6 exports the atomic write and the command-path check itself. **Decided:** proceed as written and agree the four points with M's owner before Phase 3.
3. Should the app offer the file vault? Recommended no: it needs `MINTRUN_VAULT_KEY` in plain text in every AI app's config. The Go side supports it, as the brief asks. **Decided:** no; the Go side still supports it.
4. The key store and approval timeout are read at boot, so a running `mintrun mcp` keeps the old values until its AI app restarts it. Is that acceptable, and does the app show a timeout control? **Decided:** the boot-time read is accepted. The app shows a 1–600 s timeout control and says a change applies once each AI app restarts `mintrun mcp`.
5. Approve X8, which re-reads `policy.json` on every request and turns an unreadable file into deny-all. **Decided:** approved.
6. MCP `notifications/cancelled` is ignored, because `Serve` handles one request at a time: stopping from inside the AI app is a follow-up. **Decided:** a follow-up, outside Workstream X.
7. Switching key stores moves no secrets, and there is no `secret get` to copy them. The app must tell the user to set them again. **Decided:** the app tells the user to set them again.
8. "Access ends when the task is done" holds only where the provider deletes the credential. Recommended: while a task runs, the app promises an early end only for `cloudflare` and `github` JIT leases (`ephemeral` alone cannot tell `aws` from `cloudflare`); once it ends, the app reports the entry's `revoked`, shows `expires_at` for an ephemeral lease that was not revoked (`aws`, `gcp`, a plugin), and says a static lease is the master secret itself and stays valid. **Decided:** as recommended.
9. Should the approval timeout go above 10 minutes? Telegram and Slack would then need to follow the context's deadline instead of their own 10 minutes. **Decided:** no; it stays at most 600 s.

---

## 5. Roadmap to `v0.12.0` & `v0.13.0` (approved 2026-10-18)

> Four shipped features from §3 become workstreams here, plus the §3 relay design. `v0.12.0` = **AB + AC + AD** (completed); the relay (**AE**) ships as `v0.13.0` (completed). One writer per docs file at a time (rule 17). Each workstream defines its checks before its code (layer 1).

| # | Step | Mark | Status |
| :-- | :--- | :--- | :--- |
| 1 | Release `v0.11.0` | `[SERIAL]` | ✅ Done (`v0.11.0`) |
| 2 | AB — `init policy` suggests the sandbox | `[SERIAL]` | ✅ Done (`422610f`, `e67042e`) |
| 3 | AD — app Stop end to end, and the app contract | `[PARALLEL]` with AB's code | ✅ Done (`422610f`, `e67042e`) |
| 4 | AC — `no_network` child option | `[SERIAL]` | ✅ Done (`fa117b5`, `bcf53d5`) |
| 5 | Release `v0.12.0` | `[SERIAL]` | ✅ Done (`v0.12.0`) |
| 6 | AE — team relay (`mintrun relay`) | `[SERIAL]` | ✅ Done (`eee3d19`, `252cca7`, `v0.13.0`) |
| 7 | Live-check runbook | user-run | `unresolved` (user-run) |

### Release `v0.11.0`

Covers everything since `v0.10.0` (40 commits): the macOS and Linux child sandbox, the app socket channel, `mintrun apps`, `settings.json`, and `mintrun shim`.

- **Files:** `README.md` (roadmap row), `plan.md` (header line 3 → `v0.11.0`), `progress.md` (row 17 → ✅ Done with the coverage figure). Docs only, no code.
- **Deliverables:**
  1. `[SERIAL]` In a `git archive` export of `1ac4a1e`, run §1 checks 1–5. Recommended: re-run the Linux suite and the two integration tests in a throwaway OrbStack `ubuntu:24.04`, unprivileged and as root, deleted after.
  2. `[SERIAL]` Write the three docs edits; re-measure coverage in a fresh export and confirm the figure in `progress.md` matches it exactly (rule 5).
  3. `[SERIAL]` Annotated tag. Proposed message: `mintrun v0.11.0 — an approval dialog that defaults to Deny and shows the vault and working directory, agents that cannot pick the vault or set the timeout, CLI shims, the macOS and Linux child sandbox, the macOS app channel, mintrun apps, and settings.json`. No GitHub Release.
- **Verification:**
  ```bash
  git archive 1ac4a1e | tar -xf - -C "$EXPORT" && cd "$EXPORT"
  gofmt -s -l cmd internal examples && go vet ./...
  go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -n 1 && rm -f coverage.out
  go test -race -count=1 ./... && GOOS=linux go build ./... && GOOS=windows go build ./...
  go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list
  git ls-remote origin refs/heads/main 'refs/tags/*'   # rule 25, right before push/tag
  ```
- **Approval gate:** push and tag only after a yes (layer 4). The push account is gh's active one; a 403 means it is not the expected account — ask before switching.

### AB — `mintrun init policy` suggests the sandbox

- **Files:** `internal/core/runner.go`, `cmd/mintrun/setup.go`, `cmd/mintrun/setup_test.go`, then docs (`README.md`, `AGENTS.md` rule 35, `checks.md` row 89, `progress.md`).
- **Deliverables:**
  1. `[SERIAL]` Add `func (rt *Runtime) SandboxReady() error` that reports whether this host can build the sandbox prefix, reusing the existing resolver so the check is the real one the gate runs, not a copy.
  2. `[SERIAL]` In `(*wizard).policy()`, when the sandbox is ready the suggested rule carries `Sandbox: true` plus a one-line cost note (the network stays open until AC; Keychain/D-Bus logins fail inside; do not claim `gh` works). When it is not ready, print `Sandbox: not suggested: <cause>` with no path (rule 36). Both existing-file hints show the same rule.
  3. `[SERIAL]` `TestCLIInit` pins both branches with a stubbed resolver. Mutants (run on a copy): always-on, never-on, note dropped, reason dropped, hint without the sandbox.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIInit' ./cmd/mintrun   # every new assertion shows --- PASS (rule 15)
  gofmt -s -l cmd internal examples && go vet ./... && go test -race -count=1 ./...
  ```

### AD — app Stop end to end, and the app contract

- **Files:** `cmd/mintrun/main_test.go` (`fakeApp`, new `TestCLIExecAppStop`), `README.md` (app contract), `AGENTS.md` (amend rule 42), `checks.md` (flip the X7 stop row at line 539), `progress.md`.
- **Deliverables:**
  1. `[SERIAL]` Give `fakeApp` a `stop` decision that replies `{"type":"stop"}` to a `started` line.
  2. `[SERIAL]` `TestCLIExecAppStop` runs a long child (`exec -provider cloudflare -perms static -- sh -c 'echo $$ > <pidfile>; exec sleep 60'`) on a short `os.MkdirTemp` home and asserts: it returns within 5 s; the exit code equals the observed value (pin what is seen, likely 255); exactly one audit entry with `outcome: stopped` and `via: cli`; the child pid is gone.
  3. `[SERIAL]` README states the app contract: the card shows Sandbox On/Off from the request's `sandbox` key, a missing key means an older `mintrun`; a Network line follows once AC lands; a missing `sandbox` in a `started` entry means off; Stop sends `{"type":"stop"}\n`; a connection that closes with no final entry means `mintrun` died. Amend rule 42. App-side work belongs to the separate macOS-app project (the user supplies its folder).
  4. `[SERIAL]` Mutants (on a copy): Track not wired in `bootRuntime`; stop does not close the channel; the outcome reported as `interrupted`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIExecAppStop|TestBootRuntimeSettings|TestAppTrack|TestExecBlindStop' ./...
  gofmt -s -l cmd internal examples && go vet ./... && go test -race -count=1 ./...
  ```

### AC — `no_network` child option ("Lồng kính" / glass cage)

Goal: a command that only processes local data cannot send it anywhere over the network. Implemented inside the existing sandbox, which it implies.

- **Request plumbing:** add `NoNetwork` to `ExecRequest` (`no_network,omitempty`), `PolicyRule`, `PolicyDecision` (`json:"no_network"`, always shown), and `AuditEntry` (omitempty); the CLI flag `-no-network`; an MCP property (so `TestMCPExecSchema` covers it); and the app-request key `no_network`, always sent.
- **Verdict:** `d.NoNetwork = req || rule` and it forces the sandbox on; `checkPolicy` feeds the first verdict's value back after an approval; the sandbox-prefix builder takes `noNetwork` and is called once in `decide` (rule 16 — the gate stays the single source).
- **Mechanism (detail lives in the code, not here):**
  - macOS: extend the sandbox profile to deny network egress. Any egress path that is a separate process rather than a syscall (launching a browser, a helper job, system network daemons, Apple Events, the pasteboard) is only denied where an integration probe proves the deny works, each with a positive control; anything unproven is documented as out of scope, not silently claimed.
  - Linux: the sandbox helper also enters a private network namespace before dropping privileges, leaving only loopback (down). The dry-run probe in `decide` passes `-no-network` too, so an unsupported host fails closed before any vault opens.
- **Approval text (rule 4):** a `Network: blocked` / `Network: open` line right after the `Sandbox:` line, unquoted, always shown, from the first verdict. Update every exact-text test: `TestOSApproval`, `TestTelegramApproval`, `TestSlackApproval`, `TestAppApproval`, `TestExecBlindSandbox`, `TestCheckPolicyMatchesExecBlind`, `TestMCPBridgeGovernanceTools`.
- **Stale "macOS only" texts to correct:** `runner.go` lines 39, 107, 402 (402 updates `core_test.go:1110`); `mcp.go:169`; `main.go:192`.
- **Scope note (document, do not overclaim):** `no_network` stops the command from sending. The command's output still returns to the agent, which has its own network. Writes to synced folders (iCloud, Dropbox) and files read later are a separate channel. 32-bit programs on Linux are killed by the syscall filter; setuid gains nothing inside; amd64 needs verification on a real x86-64 kernel.
- **Files:** core (`runner.go`, `sandbox_linux.go`, `core_test.go`, `sandbox_linux_test.go`, `sandbox_integration_test.go`), builtin (`mcp.go`, `appbroker.go`, `appbroker_test.go`, `builtin_test.go`, `telegram_test.go`, `slack_test.go`), CLI (`main.go`, `main_test.go`), docs. New rule 46; amend rules 4, 42, 43.
- **Deliverables:**
  1. `[SERIAL]` Fields + verdict + builder signature.
  2. `[SERIAL]` macOS profile deny + probe-gated out-of-process denies (each with its control).
  3. `[SERIAL]` Linux network namespace in the helper + dry-run probe.
  4. `[SERIAL]` Approval text line + every exact-text test.
  5. `[SERIAL]` `TestSandboxBlocksNetwork` (`//go:build integration`, macOS and Linux): the test binary re-execs itself as a probe and checks that TCP, UDP, a pathname Unix socket, and DNS are blocked inside while resolution works outside (the control), and that a local file write and `socketpair` still work; on Linux it also checks the netns inode differs and the filter is active, each with a positive control. Extend `TestLinuxSandboxSysProcAttrAndHelper`.
  6. `[SERIAL]` ~20 mutants on a copy, including one for the netns layer and one for the syscall-filter layer.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestSandboxBlocksNetwork' -tags integration ./internal/core   # macOS, and Linux in OrbStack
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestExecBlindSandbox|TestMCPExecSchema|TestOSApproval|TestTelegramApproval|TestSlackApproval|TestAppApproval|TestMCPBridgeGovernanceTools' ./...
  gofmt -s -l cmd internal examples && go vet ./... && go test -race -count=1 ./...
  GOOS=linux GOARCH=amd64 go build ./... && GOOS=linux GOARCH=arm64 go build ./... && GOOS=linux GOARCH=386 go build ./... && GOOS=windows go build ./...
  ```

### Release `v0.12.0`

Same docs-commit shape as `v0.11.0` (README roadmap row, `plan.md` header, `progress.md` row). Re-measure coverage in an export; annotated tag after a yes; `git ls-remote` first (rule 25); no GitHub Release.

### AE — team relay (`mintrun relay`), gated behind R0

One company server holds the master secrets; laptops hold only short-lived leases. **R0 is an approval gate** — the relay is a major architectural change (layer 1 pause). R1–R4 start only after the user approves R0's decisions. Ships as `v0.13.0`.

- **R0 (recommended defaults, awaiting approval):**
  - Device auth: `rand.Text()` tokens shown once, stored as SHA-256 in `<home>/relay/devices.json`, compared in constant time, managed by `mintrun relay device add|remove|list`.
  - Transport: TLS 1.3 with a required SPKI SHA-256 pin via `MINTRUN_RELAY=https://host#sha256=<hex>`.
  - Approval: Telegram or Slack, with a quoted `Device:` line.
  - Static mode refused; fail closed when the server is unreachable; leases held in memory (a restart only expires them).
  - Audit: a `minted` entry plus a final entry (`unreported` at expiry) — a documented exception to rule 8.
  - Devices cannot set the vault or the timeout; `POST /v1/check` is a read-only `CheckPolicy`; the client applies `req || verdict` for sandbox, `no_network`, and `clean_env`. Rate limits deferred.
- **R1:** extract a mint/revoke seam in `ExecBlind` (pure refactor; coverage must not drop).
- **R2:** server in `internal/builtin/relay.go` + `relay_test.go` (tested with `httptest.NewTLSServer`); CLI in `cmd/mintrun/relay.go`.
- **R3:** client (`exec -relay`, `MINTRUN_RELAY`, MCP).
- **R4:** docs, mutants, a live check, and new rule 47 carrying the §3 item 6 limits.

### Coverage Gate and Hermeticity (every workstream)

```bash
go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -n 1   # > 90% (rule 5)
grep -c -E '/(runner|sandbox_linux)\.go:' coverage.out   # > 0 (positive control the grep matches something)
go tool cover -func=coverage.out | grep -c ' 0.0%$'      # record uncovered functions
rm -f coverage.out
```

New tests stay hermetic (rule 22): a plain `go test ./...` makes zero real `sandbox-exec` / namespace-helper / network calls, and the `-tags integration` run hits the real path (the positive control). Prove it on a copy whose system binaries are logging stubs.

### Live-check runbook (user-run; tokens typed only by the user at hidden prompts)

`unresolved` until the user runs them with their own accounts; I never type a credential.

1. Real apps: `mintrun apps connect|status|disconnect`, `mintrun init mcp`, `mintrun doctor` against real Claude Code, Claude Desktop, and Cursor (L1, L2).
2. Telegram and Slack: `init telegram` / `init slack`, then three approval runs each (allow, deny, no answer) (L3 partial, L4).
3. 1Password, Bitwarden, Vercel against real accounts.
4. Linux approval with Telegram and Slack as the only channels (`OSApproval` is macOS-only).
5. The real `no_network` sandbox, including amd64 on an x86-64 host.
6. `gh` inside the sandbox (expected to fail its Keychain read; document the result).
7. The macOS app end to end: allow, deny, no answer, **stop**, pause (L3).
8. `TestSandboxHidesKeychainItem` and the `no_network` integration tests on real hardware — only after the user says yes (rule 22).

### What the Docs Must Say (rules 21, 23)

- `no_network` blocks the command's own egress, not the agent's; the output path back to the agent is not blocked.
- Out-of-process and deferred channels (synced folders, files read later, out-of-process launches) are out of scope unless a probe proves the deny; say which were proven.
- Linux: 32-bit programs are killed by the filter; setuid gains nothing inside; amd64 is marked by its verification status.
- The relay R0 limits (device tokens, the TLS pin, fail-closed, in-memory leases, the audit exception).

### Docs and Rules

- New rule 46 (`no_network`), new rule 47 (relay). Amend rules 4, 35, 42, 43.
- `checks.md`: AB → row 89; AD → the X7 stop row (line 539); AC and AE get their own rows.
- `progress.md`: a Vietnamese checkpoint per workstream, in the existing format.

### Open Questions (Recommended defaults; the user decides at approval)

1. `no_network` implies the sandbox (cannot block egress without it). **Recommended:** yes.
2. The `Network:` line wording (`blocked` / `open`). **Recommended:** those two words.
3. macOS denies only the out-of-process channels a probe proves, documenting the rest. **Recommended:** yes.
4. Linux arches: amd64 and arm64 get the filter, others are denied. arm64 is verified in OrbStack; amd64 needs an x86-64 kernel. **Recommended:** ship amd64 with its integration row `unresolved` and the docs saying so. Alternative: deny amd64 until verified.
5. `init policy` suggests the sandbox (AB) but not `no_network`. **Recommended:** yes.
6. Write restrictions under `no_network` (synced folders) are documented, not built in `v0.12.0`. **Recommended:** document only.
7. The R0 relay defaults above. **Recommended:** as listed.
8. `v0.12.0` = AB + AC + AD; the relay ships as `v0.13.0`. **Recommended:** yes.
9. Packaging means an annotated tag only, no GitHub Release (publishing needs a separate yes). **Recommended:** tag only.
10. The macOS-app project's folder, so AD's app-side contract can be checked there. **Recommended:** the user supplies it when ready.

---

## 6. Roadmap to `v0.14.0` (Workstreams AF, AG, AH & Live-Check Runbook)

> Closes the remaining technical items in [progress.md](progress.md) §3 (`TailAudit` reverse-chunk seeker, `CLAUDE_CONFIG_DIR` support, per-device relay rate limiting), builds the `app.sock` companion controller, and runs the live-check runbook.

| # | Step | Mark | Status |
| :-- | :--- | :--- | :--- |
| 1 | **AF-1** — `TailAudit` reverse-chunk seeker (via `io.ReadSeeker`) | `[PARALLEL]` with AF-2 | ✅ Done (`v0.14.0`) |
| 2 | **AF-2** — `CLAUDE_CONFIG_DIR` support in `mcpConfigs()` (`init mcp`, `doctor`, `apps`) | `[PARALLEL]` with AF-1 | ✅ Done (`v0.14.0`) |
| 3 | **AG** — Per-device rate limiting & concurrent lease cap on `mintrun relay serve` | `[SERIAL]` | ✅ Done (`v0.14.0`) |
| 4 | **AH** — `app.sock` Menu Bar (`macos/MintrunMenuBar.swift`) & `mintrun watch` controller | `[SERIAL]` | ✅ Done (`v0.14.0`) |
| 5 | **AI** — Live-check runbook execution (`gh` in sandbox, real Keychain / IDE / Linux amd64 checks) | `[SERIAL]` | ✅ Done (`v0.14.0`) |
| 6 | **AH-2** — `mintrun watch` dashboard token guard (loopback `Host` check + token in the URL `#fragment`) | `[SERIAL]`, after AH | ✅ Done (`v0.14.0`) |

### AF-1 — `TailAudit` Reverse-Chunk Seeker

- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `AGENTS.md`, `checks.md`, `progress.md`.
- **Deliverables:**
  1. `[SERIAL]` When `limit > 0` and `r` implements `io.ReadSeeker`, seek to `io.SeekEnd` (`end, err := rs.Seek(0, io.SeekEnd)`). When `err == nil && end > 0`, walk backward in 64 KiB (`64 << 10`) blocks from `end` toward `0`, assembling complete lines across chunk boundaries (no line-length cap: a 100 KiB line spanning multiple 64 KiB blocks stays intact) and matching `provider` (case-insensitive) and `failedOnly` from newest to oldest until `limit` matches are collected or offset reaches `0`. Reverse the collected slice so `fn(line, e)` is still called in chronological (log) order.
  2. `[SERIAL]` Fall back to the forward `bufio.NewReader(r)` scan when `limit <= 0`, `r` cannot seek, or `Seek(0, io.SeekEnd)` returns an error or `0`. A failed seek from the start or a `Read` error on a seekable handle (such as `EISDIR` when `audit.jsonl` is a directory in `TestMCPBridgeAuditUnreadable`) is returned immediately. Remove the `// ponytail:` debt comment on `TailAudit`.
  3. `[SERIAL]` Extend `TestTailAudit` in `internal/core/core_test.go` with:
     - a seekable `*strings.Reader` and the same reader wrapped so it cannot seek, holding a 100 KiB line across chunk boundaries, trailing and missing final newlines, and unparseable lines;
     - a custom `countingReadSeeker` proving that reading `limit=2` from the end of a 570 KiB log reads only the tail chunk (`<= 64 KiB`), not the whole file, plus a failed read and a failed seek from the start;
     - 10 mutants on a copy, all killed (see [checks.md](checks.md)).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestTailAudit|TestMCPBridgeAuditUnreadable|TestMCPBridgeGovernanceTools' ./internal/core ./internal/builtin
  ```

### AF-2 — `CLAUDE_CONFIG_DIR` Support in `mcpConfigs()`

- **Files:** `cmd/mintrun/setup.go`, `cmd/mintrun/setup_test.go`, `cmd/mintrun/apps_test.go`, `AGENTS.md` (rule 35 & rule 44), `checks.md`, `progress.md`.
- **Deliverables:**
  1. `[SERIAL]` In `mcpConfigs()` (`cmd/mintrun/setup.go`), trim the space around `os.Getenv("CLAUDE_CONFIG_DIR")` and, when the result is absolute (`filepath.IsAbs`), use `filepath.Join(dir, ".claude.json")` as Claude Code's config path; ignore relative paths (so an untrusted working directory cannot redirect config reads/writes) and fall back to `filepath.Join(home, ".claude.json")`.
  2. `[SERIAL]` Extend `TestCLIInit/mcp`, `TestCLIDoctor`, and `TestCLIApps` to pin:
     - an absolute `CLAUDE_CONFIG_DIR` redirects Claude Code's `.claude.json` lookup in `init mcp`, `doctor`, and `apps status`, and a value padded with space and a newline still works in `init mcp`;
     - a relative `CLAUDE_CONFIG_DIR` (`relative-claude`) is ignored in favor of `<HOME>/.claude.json`;
     - 3 mutants on a copy, all killed (no `IsAbs`, no `TrimSpace`, the wrong variable).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIInit/mcp|TestCLIDoctor|TestCLIApps' ./cmd/mintrun
  ```

### AG — Per-Device Rate Limiting & Active Lease Cap on `mintrun relay serve`

- **Files:** `internal/builtin/relay.go`, `internal/builtin/relay_test.go`, `README.md`, `AGENTS.md` (rule 47), `checks.md`, `progress.md`.
- **Deliverables:**
  1. `[SERIAL]` Add per-device token-bucket rate limiting to `RelayServer` (default: 300 requests/min, burst 60; set through the exported `RatePerMin` and `Burst` fields (0 or less turns it off; `mintrun relay serve` uses the defaults) and an injectable `Now func() time.Time` clock so tests never `time.Sleep`), enforced after authentication, per `dev.Name`, before `/v1/check`, `/v1/mint`, or `/v1/revoke` runs. Exceeding the bucket returns HTTP `429 Too Many Requests` with `Retry-After: 1` and `{"error": "rate limit exceeded"}`.
  2. `[SERIAL]` Add a per-device active concurrent lease cap on `/v1/mint` (the `MaxLeases` field, default `DefaultMaxActiveLeasesPerDevice = 32`, 0 or less turns it off): when a device already holds the maximum number of unrevoked leases, `/v1/mint` returns HTTP `429 Too Many Requests` with `Retry-After: 1` and the error `too many active leases for device` before minting a new lease, while other devices can still mint and the limited device can still call `/v1/revoke` to free a slot. Disambiguate colliding active lease IDs with a `-<task>` suffix.
  3. `[SERIAL]` Add `TestRelayRateLimitAndLeaseCap` in `internal/builtin/relay_test.go` and 11 mutants on a copy, all killed (see [checks.md](checks.md)).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestRelay' ./internal/builtin
  ```

### AH — `app.sock` Menu Bar (`macos/MintrunMenuBar.swift`) & `mintrun watch` Controller

- **Files:** `internal/builtin/watch.go`, `internal/builtin/watch_test.go`, `cmd/mintrun/watch.go`, `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`, `macos/MintrunMenuBar.swift`, `macos/build.sh`, `macos/README.md`, `.gitignore`, `README.md`, `AGENTS.md` (rule 48), `checks.md`, `progress.md`.
- **Deliverables:**
  1. `[SERIAL]` Built-in `mintrun watch [-http 127.0.0.1:0]` subcommand + `builtin.WatchServer` listening on `<home>/app.sock` (`0600`, clean-stale/refuse-live) and serving a loopback CSRF-protected (`X-Mintrun-Watch: 1`) dashboard and JSON API (`/api/state`, `/api/decide`, `/api/stop`, `/api/pause`).
  2. `[SERIAL]` Native single-file macOS Menu Bar companion in `macos/MintrunMenuBar.swift` + `macos/build.sh` (`NSStatusBar` + `AppKit` + `POSIX AF_UNIX` socket server on `~/.mintrun/app.sock` + native `NSAlert` approval dialogs, active-lease Stop menu items, Pause toggle, and `mintrun apps` integration).
  3. `[SERIAL]` `TestWatchServer`, `TestCLIWatch`, and 6 mutants on a copy (all killed).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestWatchServer|TestCLIWatch' ./internal/builtin ./cmd/mintrun && ./macos/build.sh
  ```

### AI — Live-Check Runbook Execution

- **Deliverables:**
  1. `[SERIAL]` Executed all non-destructive local and container probes on macOS 27.0 and in Docker (`linux/arm64` and `--platform linux/amd64`):
     - Probe 1: `./mintrun doctor`, `./mintrun apps status`, and `./mintrun apps connect -dry-run` on the host.
     - Probe 2: `go test -tags integration -count=1 -v ./internal/core ./internal/builtin` on macOS 27.0 (`TestSandboxHidesHome`, `TestSandboxHidesKeychainItem`, `TestSandboxBlocksNetwork`, `TestKeychainVaultRealKeychain`).
     - Probe 3: `gh auth status` inside the `mintrun` macOS sandbox (`sandbox-exec`) confirming `~/Library/Keychains` and Security Mach services are blocked (`open ~/.config/gh/hosts.yml` works while Keychain token lookup fails unless `GH_TOKEN` is injected via `Lease.Env`).
     - Probe 4: `GOOS=linux GOARCH=amd64` and `GOOS=linux GOARCH=arm64` integration tests (`TestSandboxHidesHome`, `TestSandboxBlocksNetwork`) inside privileged Linux containers (`golang:1.24-bookworm`).

### AH-2 — `mintrun watch` Dashboard Token Guard

- **Files:** `internal/builtin/watch.go`, `internal/builtin/watch_test.go`, `cmd/mintrun/watch.go`, `cmd/mintrun/watch_test.go`, `macos/MintrunMenuBar.swift`, `macos/README.md`, `README.md`, `docs/threat-model.md`, `AGENTS.md` (rule 48 and the new rule 51), `checks.md`, `progress.md`.
- **Deliverables:**
  1. `[SERIAL]` `(*WatchServer).DashboardURL(addr string) string` (`internal/builtin/watch.go`) is the only place the dashboard URL is built: it returns `http://<addr>/#<token>`, so the banner `cmd/mintrun/watch.go` prints, the macOS menu bar's parser, and `TestWatchDashboardBanner` cannot drift. `ServeHTTP` refuses any `Host` that is not the loopback address and port it listens on, before the `/api/` token check (`X-Mintrun-Token`, `subtle.ConstantTimeCompare`) and the `X-Mintrun-Watch: 1` check on every mutating `POST`; `GET /` stays tokenless because a page load cannot set a header, and the page it serves reads the token from `location.hash`.
  2. `[SERIAL]` `TestWatchDashboardBanner` (`cmd/mintrun/watch_test.go`) runs the real `cmdWatch` through `capture`, matches the printed banner against `^http://127\.0\.0\.1:[0-9]+/#([A-Z2-7]+)$`, then sends the captured token to the live `/api/state` (`200`) and none and `<token>x` (`403`). `TestWatchServer` pins the `loopbackHost` table and both header refusals; `TestCLIWatch` still pins the usage text and the non-loopback `-http` refusal.
  3. `[SERIAL]` `docs/threat-model.md` §Approval, `AGENTS.md` rules 48 and 51, `README.md`, and `macos/README.md` describe this guard and its limits (a local user who reads the terminal or `mintrun`'s memory still has the token; the menu bar's "open dashboard" opens the fragment-less URL, so it shows the refusal).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestWatchServer|TestWatchDashboardBanner|TestCLIWatch' ./internal/builtin ./cmd/mintrun
  ```

## 7. Approval Hints (`Hints:` Line, 2026-10-19)

> A deterministic first step before any semantic screen of a command: every approver (the dialog, Telegram, Slack, `mintrun watch`, and through it the menu bar app) reads a closed-vocabulary risk hint computed from argv and the provider, ahead of every agent field. No model, no network call, no new dependency, and the hints decide nothing.

| # | Step | Mark | Status |
| :-- | :--- | :--- | :--- |
| 1 | `approvalHints` and the `Hints:` line in `core.ApprovalText` | `[SERIAL]` | ✅ Done (`76f9ce0`) |
| 2 | Exact-text tests: `TestApprovalHints`, `TestOSApproval`, and the Telegram, Slack, relay, and watch texts | `[SERIAL]` | ✅ Done (`76f9ce0`) |
| 3 | Mutants on a copy | `[SERIAL]` | ✅ Done (24/24 killed) |
| 4 | Docs: `AGENTS.md` rule 4, `README.md`, `macos/README.md`, `checks.md`, `progress.md` | `[SERIAL]` | ✅ Done |

### Hints Line

- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/telegram_test.go`, `internal/builtin/slack_test.go`, `internal/builtin/relay_test.go`, `internal/builtin/watch_test.go`, `AGENTS.md` (rule 4), `README.md`, `macos/README.md`, `checks.md`, `progress.md`.
- **Deliverables:**
  1. `[SERIAL]` `approvalHints(req ExecRequest) []string` next to `ApprovalText`, with the vocabulary in one ordered slice (`approvalHintRules`) and each provider's own hosts in `approvalOwnHosts`; `strings`, `slices`, and `net/url` only, no `regexp`. `ApprovalText` writes `Hints: none` or the labels joined by `, ` under `Network:`, or under `Device:` when it is set, unquoted and ahead of `Provider:`.
  2. `[SERIAL]` `TestApprovalHints` (the table test), and five whole dialog texts plus a long, cut request in `TestOSApproval`; the Telegram, Slack, relay, and watch tests expect the new line.
  3. `[SERIAL]` Mutants on a copy, each compiled first: the line after `Command:`, quoted, or dropped when empty; the labels sorted; `rm` matched as a substring; the provider's own URL called external; a bare `-f` flagged; and 17 more (see [checks.md](checks.md)).
- **Verification:**
  ```bash
  go test -count=1 -v -run '^(TestOSApproval|TestApprovalHints|TestMintLeaseAndRelayClient|TestTelegramApproval|TestSlackApproval|TestRelayEndToEnd|TestWatchServer)$' ./internal/core ./internal/builtin
  ```

