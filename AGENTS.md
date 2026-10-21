# AGENTS.md — `mintrun` Agent Harness Specification

> **Cherny-Inspired 7-Layer Agent Harness** for the `mintrun` repository (Zero-Knowledge JIT Credential Enclave & Blind CLI Runner).

---

```xml
<prompt>
<goal>
Complete {{TASK}} inside a structured harness, not an open-ended chat.
A harness is the plan, context boundaries, tools, verification checks, and invariant rules wrapping the model.
Leave behind a working deliverable, a factual verification report, and an updated AGENTS.md.
Stop when every check passes or the agreed run limit is reached.
</goal>

<role>
Act as the lead engineer who designs, runs, and maintains this harness for `mintrun`.
Read the project instructions (`AGENTS.md`, `README.md`) and inspect existing code before making edits.
Plan and decompose the work; implement directly; delegate bounded, non-overlapping tasks to subagents when appropriate.
Record architectural and harness decisions as they happen.
</role>

<principles>
Apply Boris Cherny's agent harness operating habits combined with `mintrun` core engineering principles:
- Start in plan mode and align on the plan before writing code.
- Give the model a deterministic way to verify its own work (`go vet`, `go test`, `./mintrun`).
- When a mistake happens or a new project constraint is discovered, codify a rule in `<learned_rules>` inside `AGENTS.md`.
- Only run parallel sessions or subagents on strictly disjoint file scopes.
- YAGNI & Zero External Dependencies: 100% Go standard library only (`go.mod` must never include third-party packages).
</principles>

<inputs>
Task: {{TASK}}
Working directory & output path: {{OUTPUT}} (default: repository root `.`)
Acceptance checks: {{CHECKS}}
  - `gofmt -s -w . && go vet ./...`
  - `go test -count=1 -cover ./...` (total statement coverage must remain > 90%)
  - `go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list`
Source material: {{SOURCES}}
  - `cmd/mintrun/main.go` & `cmd/mintrun/main_test.go` (CLI entrypoint & end-to-end subcommand tests)
  - `internal/core/plugin.go`, `internal/core/runner.go` & `internal/core/core_test.go` (Plugin ABI, ExecBlind lifecycle, Policy Engine, Scrubber, Audit Logger)
  - `internal/builtin/keychain.go`, `internal/builtin/cloudflare.go`, `internal/builtin/mcp.go` & `internal/builtin/builtin_test.go` (Built-in Vaults, JIT Providers, MCP Bridge)
Allowed changes: {{SCOPE}}
Run limit: {{LIMIT}} (default: max 3 retries per failing step)
Populate these fields before starting. If missing details would materially change the outcome, ask one focused question.
</inputs>

<layer_1_plan>
Enter plan mode before editing. Write the plan as discrete steps with a concrete output and a runnable check per step:
- Name the exact files each step will read and write.
- Mark steps that can run in parallel (`[PARALLEL]`) vs. sequential steps (`[SERIAL]`).
- Define the verification checks before writing implementation code, not after.
Save the plan to `plan.md` and pause for approval when a task introduces major architectural changes.
</layer_1_plan>

<layer_2_context>
Load only the context required for the active step:
1. Read `AGENTS.md` and only the source files relevant to the current step.
2. Pass the step specification, its inputs, and its verification check.
3. Keep verbose logs and raw command dumps out of the primary reasoning context.
4. Summarize step outcomes as: `paths | verdicts | evidence`.
Reserve the main context window for architecture and decision-making, not raw search dumps.
</layer_2_context>

<layer_3_tools_hooks>
Whenever a rule must be enforced every time (formatting, static analysis, test coverage, secret scrubbing), turn it into an executable command or check rather than prose advice. A prompt is for judgment; commands are for enforcement:
- Standard verification pipeline for `mintrun`:
  - Format & Static Analysis: `gofmt -s -w . && go vet ./...`
  - Coverage Gate (> 90%):
    `go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -n 1 && rm -f coverage.out`
  - Reproducible Binary Build & Smoke Test:
    `go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list`
- Never rely on the model remembering to apply a check speculatively.
If a required tool is missing, name the blocker and preserve all steps that can still complete.
</layer_3_tools_hooks>

<layer_4_permissions>
Verify permissions before running the harness. Keep all edits strictly within `{{SCOPE}}`. Configure sandbox boundaries when operating in untrusted environments:
- Ask before publishing (`git push`), creating release tags, calling live external cloud APIs with real credentials, or mutating user data under `~/.mintrun/`.
- Never allow two concurrent sessions or subagents to edit the same file.
- Maintain a clean, recoverable git state before executing high-risk refactors.
</layer_4_permissions>

<layer_5_verification>
Every step must self-verify using real signals: unit/integration tests, binary builds, coverage reports, and actual CLI outputs. Trust comes exclusively from observed execution results.
Record verification results in `checks.md` (or the final verification table) with one row per requirement:
`step | requirement | verdict | evidence`
Use `pass`, `fail`, or `unresolved`. Keep any missing evidence explicitly visible.
</layer_5_verification>

<layer_6_feedback>
Maintain two feedback loops:
- Error Recovery: when a step fails verification, re-run only that step with the failure reason, exact `stderr`/test output, and a "fix this step only" boundary. Cap retries at 3 attempts.
- Memory Loop: whenever a bug, subtle edge case, or user correction occurs, append an invariant rule to `<learned_rules>` in `AGENTS.md` so future sessions never repeat the mistake.
</layer_6_feedback>

<layer_7_completion>
Before finishing, evaluate the completion checklist against `{{CHECKS}}`. Every item must have observable proof:
- All target outputs exist and compile cleanly.
- Every check passes against the latest source tree and rebuilt `./mintrun` binary.
- All errors are resolved or explicitly documented.
- `AGENTS.md` includes any new rules learned during the run.
If the run limit is reached or blocked, return partial status with exact verdicts showing what passed.
</layer_7_completion>

<execution_loop>
1. Read `plan.md` and select the next ready step(s).
2. Execute independent steps in parallel.
3. Verify every output against its check (`go vet`, `go test`, `./mintrun`).
4. Retry only failed steps (up to `{{LIMIT}}`); never discard an entire batch for an isolated failure.
5. Merge accepted outputs and re-run the full repository check suite.
6. Continue until complete, blocked, or `{{LIMIT}}` is reached. Never loop infinitely.
</execution_loop>

<handoff>
After each phase in a multi-phase task, update `progress.md`:
- Plan: completed, active, and blocked steps.
- Outputs: exact relative paths to created or modified files.
- Decisions: what changed in the codebase or harness and why.
- Open issues: errors, uncertainties, and external blockers.
- Next step: the next immediately actionable step.
When resuming a session, read `AGENTS.md`, `plan.md`, and `progress.md` first, then continue from the recorded checkpoint.
</handoff>

<delivery>
Return `{{OUTPUT}}`, `plan.md`, `checks.md`, `progress.md` (when applicable), and the `AGENTS.md` diff.
State clearly what was verified, what passed, and what remains unresolved.
Report test coverage and usage metrics strictly from real command execution—never estimate or infer numbers from the prompt.
</delivery>
</prompt>
```

---

## `<learned_rules>` — Project Invariants

> Full rule mechanisms, test citations, and mutant histories live in [docs/learned-rules.md](docs/learned-rules.md). Keep rules in `AGENTS.md` concise (`<= 3` sentences per rule) so session context stays lean.

1. **Zero External Dependencies:** `go.mod` must only declare the module path and Go toolchain version (`go 1.24.0`). All cryptographic and network protocols (RS256 JWT, AWS SigV4, AES-256-GCM, SHA-256 pinning, MCP JSON-RPC 2.0) must be implemented using 100% Go standard library packages.
2. **No GitHub Actions CI (`.github/workflows`):** This repository does not use GitHub Actions. Never create or re-introduce a `.github/` directory.
3. **Zero-Secret & Zero-PII Leak Invariant:**
   - Every credential handled at runtime (Master Secret, `Lease.Env`, `Lease.Redact`) must pass through `core.Scrub()` (covering Raw, Base64, RawBase64, Hex, and URL-encoded forms) before reaching `stdout`, `stderr`, or `~/.mintrun/audit.jsonl`.
   - Never commit local absolute filesystem paths (such as user home directories or workspace paths), hostnames, device identifiers, or real tokens in source code, tests, comments, or documentation (`README.md`, `AGENTS.md`). Always use relative paths and `-trimpath` when building binaries.
4. **Approval Text Quotes Every Agent Field; the Dialog Literal Holds Only Escapes AppleScript Reads:** Every approver shows `core.ApprovalText`. Its first two lines under the header are `Sandbox: on` or `Sandbox: off` and `Network: blocked` or `Network: open`, written by mintrun and unquoted, ahead of every agent field, so no long request pushes them behind the TRUNCATED warning; they show the sandbox and network flags of the verdict that asks, never only the request's flags (rules 43, 46).
5. **Verified Statement Coverage (`> 90%`):** Never report estimated coverage numbers. Always execute `go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out` and remove temporary `coverage.out` artifacts before committing.
6. **Keep `./mintrun` Binary Synchronized:** After modifying any file under `cmd/` or `internal/`, rebuild with `go build -trimpath -o mintrun ./cmd/mintrun` so local CLI and MCP server executions run the latest code.
7. **Lease IDs Are Public Handles, Never Secrets:** `Lease.ID` is returned to agents (`ExecResult.LeaseID`, MCP) and written to `audit.jsonl`, so providers must set it to an opaque non-secret handle (e.g. `gh-inst-<installation_id>-<unix>`). A credential needed only by `Revoke` goes in `Lease.RevokeSecret` (`json:"-"`, never serialized); the runner still scrubs `lease.ID` against all known secrets as defense in depth.
8. **Scrub Every `ExecBlind` Exit Path, Not Just Successful Output:** Errors (especially `provider.Mint` failures, which can echo plugin stderr or API response bodies), `LeaseID`, and the audit `command`/`error` fields must all pass through `Scrub()` with the master secret plus every lease secret. Return scrubbed error text with `%s`, never wrap a raw error that may contain a secret with `%w`.
9. **File Vault Requires a Passphrase, Derived With a Salted KDF:** The AES-256-GCM fallback vault (`internal/builtin/keychain.go`, the at-rest store on non-macOS hosts) must never derive its key from the filesystem path or any other guessable value. Require a non-empty `MINTRUN_VAULT_KEY` and derive the key with `crypto/pbkdf2.Key(sha256.New, pass, salt, …)` using a per-vault random salt persisted in `vault.json` (`__salt__`).
10. **Plugins Cannot Shadow Built-ins, Escape Their Directory, or Install Unverified:** `Registry.Register` must reject a non-builtin plugin whose name matches an existing built-in vault/provider/bridge. Any plugin name used as a path segment must pass `safePluginName` (single segment, no `.`/`..`/separators) on both install and remove.
11. **Child Env Never Carries the Vault Passphrase or Relay Token; Clean Mode Only Tightens:** `ExecBlind` builds the child environment with `childEnv`. `MINTRUN_VAULT_KEY` and `MINTRUN_RELAY_TOKEN` are never inherited, even when `allowed_env` matches them (`["*"]` included).
12. **Providers Scrub Their Own Derived Secrets; Static Mode Is Explicit and Key-Free:** The runner knows the master secret only as one whole string, so a provider that derives sub-secrets (a signed JWT assertion, a parsed private key from a JSON master) must scrub them from its own error text (e.g. `GCPProvider.postForm`) and list them in `Lease.Redact`.
13. **GCP Revocation Is Best-Effort; Revocation Tokens Go in the Body:** Google does not revoke service-account access tokens server-side and fixes their lifetime (≤1h), so `revoked=false` is expected and neither `-ttl` nor `max_ttl_seconds` can shorten a GCP lease; never document otherwise. Send revocation tokens in the POST body, never in a URL query.
14. **Secrets Reach Helper CLIs on stdin, From Absolutely Resolved Binaries:** Pass secrets to helper CLIs (e.g. `secret-tool store`) on stdin, never argv (visible in `ps`). Use an `exec.LookPath` result only when `err == nil`, because Go returns a relative-path match together with `exec.ErrDot`. `mintrun secret set` reads piped stdin whole, so multi-line secrets (service-account JSON, PEM) are never truncated to their first line, and a failed stdin read is fatal so a partial read never overwrites a stored secret.
15. **Run Each Step's Verification Check Verbatim and Confirm It Selects the New Tests:** A `go test -run` regex in `plan.md` that matches no test still exits `ok`, so a renamed or differently named test silently drops out of the check (for example, `TestKeychainLinux` does not match `TestKeychainVaultLinuxSecretTool`). Run each step check with `-v` and confirm every new test appears as `--- PASS`; fix the regex or the test name when it does not.
16. **MCP Governance Tools Are Read-Only Views of the Real Gate:** `mintrun_policy_check` must call `core.(*Runtime).CheckPolicy`, the same function `ExecBlind` enforces through `checkPolicy`, and must never open a vault, mint, exec, call `ApprovalFunc`, or write `audit.jsonl`. Add every new gate rule to `CheckPolicy`, never to `ExecBlind` alone (`TestCheckPolicyMatchesExecBlind` pins each denial reason to the `ExecBlind` error).
17. **Format Only This Checkout:** `.claude/worktrees/` can hold other sessions' git worktrees, and `gofmt` walks into dot-directories (unlike `go vet ./...`, which skips them), so `gofmt -s -w .` can rewrite another session's files. Run `gofmt -s -l .` first; if it lists anything under `.claude/`, format the repo's own packages only (`gofmt -s -w cmd internal examples`). The same goes for `grep -r .` scans: scope repo scans to `cmd internal examples` so they never match stale copies under `.claude/worktrees/`.
18. **Keychain Secrets Travel on `security -i` stdin, Long Ones in Checksummed Parts, and Keystore Fallbacks Are Loud:** `security add-generic-password -w <secret>` puts the secret on argv, so `keychainWrite` sends one `add-generic-password -U … -X <hex>` line to `/usr/bin/security -i` on stdin. `security -i` splits a line longer than 4095 bytes (newline included) and stores a corrupted item, so such a line is never sent.
19. **A Capped Stream Never Ends Inside a Secret:** `cappedBuffer` keeps the first `MaxOutputBytes` (4 MiB) of each child stream and never fails a `Write`, since an `EPIPE` would kill a chatty child. `Scrub` matches whole secrets only, so a cut stream first loses any tail that is a proper prefix of a secret variant, and the trim repeats until no tail is one; then it is scrubbed, `[MINTRUN:TRUNCATED n bytes]` is appended, and `truncated` is set.
20. **The Blind Child Runs in Its Own Process Group, So `main` Must Catch Every Stop Signal:** On Unix, `killProcessGroup` sets `Setpgid` and a `cmd.Cancel` that SIGKILLs `-pgid`, but only while the child is unreaped (`Signal(0)` returning `os.ErrProcessDone` means its pid may already be reused). `cmd.WaitDelay` (`PipeWaitDelay`, 5 s) bounds the wait for pipes a leftover process still holds;.
21. **Report Revocation Honestly; SigV4 Signs Every Header It Sends:** A provider whose credential cannot be invalidated early returns an error from `Revoke`, so the lease reports `revoked: false`; never return `nil` for a no-op revoke, and never document a lease as revoked on exit unless its provider deletes it. AWS STS credentials are expires-only, with the lifetime clamped to 900–43200 s;.
22. **`go test ./...` Stays Hermetic, and Every Scan Needs a Positive Control:** Unit tests never run the real `security`, `osascript`, `op`, `stty`, `sandbox-exec`, the Linux namespace sandbox helper, or a cloud API: they inject mocks (`securityPath`, `sttyPath`, `SecretTool`, `SandboxExecPath`, `LinuxSandboxPath`, a stub `op` first on `PATH`, `ForceFile: true`, `t.TempDir()` or `MINTRUN_HOME`). A test against the real system goes in a `//go:build integration` file (`keychain_integration_test.go`, `sandbox_integration_test.go`) and runs only with `-tags integration`.
23. **Never Claim the Blind Child Is Isolated From the Master Secret:** The child runs as the same user as `mintrun`, so it can query the keystore itself (any same-user process running `security` reads a Keychain item `security` created, without a prompt), read `vault.json`, and on Linux read `mintrun`'s environment, `MINTRUN_VAULT_KEY` included (`/proc/$PPID/environ`). On macOS 27.0, `ps -E -ww -p $PPID` and `sysctl KERN_PROCARGS2` returned only the parent's arguments, while the same reads of the child's own pid showed its environment (the positive control); older releases and a debugger attach are untested, so never document the environment as safe.
24. **Static Mode Is an Explicit Request, Never a Fallback:** A provider injects its master secret as-is only when the request carries `mode=static` or the `static` permission, the exact test `CheckPolicy` gates with `allow_static`; a provider's static condition must never be broader than that gate (rule 16). A credential or scope the provider cannot mint from fails with an error that names the opt-in (the `static` permission plus `"allow_static": true`) and quotes neither the secret nor the request.
25. **Check Remote Heads and Tags Right Before Every Push:** Several sessions may push and tag this repo concurrently. Right before `git push`, run `git ls-remote origin refs/heads/main 'refs/tags/*'` and compare both heads and tags with what the pushed commits assume: an earlier fetch or memory is not enough, and a push that fast-forwards says nothing about tags. If either moved, fetch, update any affected documentation, and check again.
26. **Request Params Never Change How the Master Is Parsed:** A provider parses its master secret the same way whatever the request carries, and a param overrides only the field it names: `params.installation_id` fills in the installation ID (rule 27), never how the bearer is derived. A bearer that still holds `-----BEGIN` is refused before any request, and `doGitHubJSON` scrubs the bearer from an API error body, because the runner scrubs only the whole master (rule 12).
27. **A Param That Picks What Gets Minted Is Bound by the Master's Pin and an Exact, Fail-Closed Allowlist:** `params.installation_id` picks the GitHub App installation a token is minted for. `GitHubProvider.Mint` refuses one that differs from the installation the master pins (`<app_id>:<installation_id>:<pem>`, `<installation_id>:<jwt>`) before any request, with an error that quotes neither the master nor either ID;.
28. **1Password Secrets Travel on `op` stdin, and `op`'s stdout Is Never Quoted:** `OnePasswordVault.SetSecret` pipes a JSON item template (a `CONCEALED` `credential` field) to `op item create --format json -` on stdin, never `credential=<secret>` on argv (rule 14). `op` adds a new item on every create and `op item get` refuses an ambiguous title, so every other item with the same title in the new item's vault is then archived (`op item delete --archive`); a failed archive only warns, because the new secret is already stored.
29. **A Fallback Store Removes the Stale Keystore Item or Fails Loudly:** `GetSecret` reads libsecret, then the macOS Keychain, then the file vault, so a keystore item left behind when a store falls back to the file vault would shadow the new secret. After a failed keystore store, `SetSecret` writes the file vault first and only then calls `deleteKeystores`, which `DeleteSecret` shares: it clears the libsecret entry and deletes the Keychain item plus the parts its header names.
30. **A Keystore Store Removes the File-Vault Copy, or Warns That It May Remain:** `GetSecret` falls back to the file vault when a keystore lookup fails, so an older `vault.json` copy of a key that libsecret or the Keychain now holds would come back after a failed lookup. After a successful keystore store, `SetSecret` calls `dropFileCopy`, which removes the key through `deleteFileSecret`.
31. **Approval Channels Race, and Only an Answer Counts:** `-approve`, `MINTRUN_APPROVE=1`, and policy `require_approval` call `core.FirstApproval(builtin.AppApproval(rt, core.OSApproval), builtin.TelegramApproval(rt), builtin.SlackApproval(rt))`, which `bootRuntime` sets for every command (rule 45): the macOS app answers when it runs, and the dialog shows only when the app's socket cannot be dialed (rule 42).
32. **Example Plugins Keep the Built-ins' Secret Rules, Proven on Stand-ins:** Each `examples/plugins/<name>/run` is one Python 3.9+ standard-library script. It validates input with `re.fullmatch` (a `$` anchor accepts a trailing newline), runs helpers by an absolute `shutil.which` path, passes secrets on `stdin` or in the helper's environment, never `argv` (rule 14), never quotes a helper's `stdout`, scrubs every secret it knows (raw and JSON-escaped) from its errors, and reports an unexpected exception by type only.
33. **A Bare Plugin Name Installs the Built-in Copy, Through the Same Checks as a Directory:** `examples/plugins/embed.go` embeds the example plugins (`//go:embed bitwarden vercel postgres-jit`), so a new example directory must be added to that line. `mintrun plugin install <name>` copies the embedded plugin to a temporary directory, installs it with `core.InstallPlugin` (`safePluginName`, the entrypoint checks, `Builtin: false`; rule 10), and removes the copy.
34. **Slack Approval Polls a DM's Reactions, and Only the Stored User's ✅ or ❌ Answers:** Slack's buttons post to a public Request URL and Socket Mode needs a WebSocket client, so `SlackApproval` posts the request with `chat.postMessage` to `channel=<user_id>` (the bot's DM with that user), adds ✅ (`white_check_mark`) and ❌ (`x`) with `reactions.add`, and polls `reactions.get` with `full=true` every `slackPoll` (3 s, within Tier 3).
35. **`mintrun init` Checks Before It Stores and Asks Before It Writes; `doctor` Only Reads:** `init` validates a master secret before `SetSecret`: a GitHub App ID and installation ID are digits and the PEM parses with `builtin.ParseRSAPrivateKey` (an empty installation ID stores `<app_id>::<pem>` and prints the `allowed_installations` hint, rule 27); an AWS key ID matches `^(AKIA|ASIA)[A-Z0-9]{16}$`, its secret is 40 characters, and an `ASIA` key needs a session token; a GCP key file needs `client_email` and a `private_key` that parses; a Cloudflare token is `[A-Za-z0-9_-]+`.
36. **Only a Missing `policy.json` Means No Policy:** `LoadPolicies`, which `decide` runs on every request (rule 16), loads no rules only when `os.Lstat` reports `fs.ErrNotExist`. It asks `Lstat`, not the `ReadFile` error, because `ReadFile` also reports a symlink to a missing file as `ErrNotExist`.
37. **A Missing Secret Names Its Fix Once, in the Vault:** Only the vault can tell a miss from a failure, so the file vault's miss ends with the command that stores the key: `(run mintrun init <step>)` for a key `mintrun init` sets up (`github`, `aws`, `gcp`, `cloudflare`; `approval-telegram` is the `telegram` step and `approval-slack` the `slack` step), `(run mintrun init <type> -account <account>)` for an account of one of those four (rule 56), and `(run mintrun secret set <key>)` for any other.
38. **Output That Confirms a Secret Names Only the Key and the Vault:** `secret check` and `doctor` (rule 35) say whether a secret is set and in which vault, never its value or anything derived from it (its length, a prefix, a hash): each narrows a guess, and a length alone tells one kind of credential from another. On success `secret check` prints exactly `Secret "<key>" is configured in vault "<vault>" (value hidden).` and exits 0.
39. **CLI Shims Default to Block-and-Redirect, Env Only Tightens, and Auto-Wrap Resolves an Absolute Real Binary Outside `<home>/shims`:** When `os.Args[0]` has a base name in `shimTools` (`gh`, `aws`, `gcloud`, `wrangler`, `vercel`, `psql`, with or without `.exe`), `main` dispatches to `runShim`. `loadShimConfig` checks `<home>/shims/config.json` with `os.Lstat` so only a missing file means no config (a directory, a dangling symlink, or an unreadable file fails closed with the `*fs.PathError` cause and never the local path; rule 36), decodes with `DisallowUnknownFields`, and rejects unknown tools or modes other than `"block"` and `"auto"`.
40. **Shim Install and Remove Edit a Shell Profile Only After a Yes, Backed Up, Where a Link Points, and Only `mintrun`'s Own Line:** `shim install` puts `shimProfileLine` (`export PATH='<home>/shims':"$PATH" # mintrun-shim`, the directory through `shellQuote`) last in `~/.zshenv` and `~/.zshrc`, creating them, and in `~/.zprofile` and `~/.bashrc` only when they exist. It goes last because Homebrew's `~/.zprofile` line puts its own directory first, and a last line without a newline gets one first.
41. **The MCP Client Name Is Self-Reported, Filtered, and Local to One `Serve` Call:** `Serve` reads `initialize`'s `params.clientInfo.name` into a variable local to that call, never a field of `MCPBridge`, because one bridge serves every `Serve` call. `clientName` passes it through `shortLabel`, which keeps only `[A-Za-z0-9._ ()@-]` and then cuts to 64 bytes, and an empty result records no client.
42. **The App Socket Is Trusted Like `policy.json`, and Only a Failed Dial Falls Back:** The macOS app listens on `<home>/app.sock`. mintrun dials it once per approval (`AppApproval`) and once per running task (`AppTrack`), and sends newline-delimited JSON with `"v":1`. Neither checks the socket's owner or peer, and neither has build tags.
43. **The Sandbox Only Tightens, Fails Closed Before the Vault, and Is Documented No Wider Than Its Tests:** Policy `"sandbox": true`, the CLI's `-sandbox`, and MCP `sandbox` run the blind command inside the OS sandbox (`sandbox-exec` on macOS, user and mount namespaces on Linux), and a request can only add it (`req.Sandbox || rule.Sandbox`, rule 11). `checkPolicy` feeds the first verdict's sandbox into the second `decide` after an approval, so a rule changed while a human approves can add the sandbox but never drop it.
44. **`mintrun apps` Edits Only `mintrun`'s Entry, Byte for Byte, and Never Quotes a Config:** `mintrun apps status|connect|disconnect` is the installer the macOS app runs. It never asks, and it prints one JSON row per app: `status` reports `found`, `installed`, and `matches` (the entry runs this binary with `["mcp"]`), and `connect` and `disconnect` report a `change` of `add`, `update`, `remove`, or `none`.
45. **`settings.json` Is Checked Like `policy.json`, Read Once, and Loses to the Environment; a CLI Run Asks the App First and Says It Came From the CLI:** The macOS app writes `<home>/settings.json`, and `bootRuntime` reads it once per process through `loadSettings`, before any command or shim runs, so a running `mintrun mcp` keeps the values it read until its AI app restarts it. Only a not-exist `Lstat` means no settings (rule 36).
46. **`no_network` Implies the Sandbox, Only Tightens, Fails Closed Before the Vault, and Uses Two Layers on Linux (`CLONE_NEWNET` + `seccomp-bpf`):** Policy `"no_network": true`, CLI `-no-network`, and MCP `no_network: true` block network egress inside the child (`d.NoNetwork = req.NoNetwork || rule.NoNetwork`) and imply the OS sandbox (`d.Sandbox = req.Sandbox || rule.Sandbox || d.NoNetwork`), so a caller can add `-no-network` per run without ever loosening a policy that sets it (rule 11).
47. **Team Relay Holds the Masters on One Server, Pins TLS 1.3 SPKI, Hashes Device Tokens, Refuses Static Mode, Rate-Limits Checks and Mints but Never Revokes, Fails Closed, and Audits Both Mint and Outcome:** `ExecBlind` acquires its lease through `acquireLease`: when `rt.Relay != nil` (`builtin.NewRelayClient` from `-relay` or `MINTRUN_RELAY`), it delegates policy evaluation, human approval, vault lookup, and minting to the relay server's `POST /v1/mint` (`Runtime.MintLease`), and the revoke closure it returns calls `RelayClient.Revoke` (`POST /v1/revoke`, a 10 s timeout, an error read as `revoked: false`), which on the server runs the `finish` that `MintLease` returned.
48. **`TailAudit` Seeks Backward in 64 KiB Chunks When `limit > 0`, and `mintrun watch` Serves `app.sock` Plus a Loopback CSRF-Protected Dashboard:** When `limit > 0` and `r` implements `io.ReadSeeker` whose `Seek(0, io.SeekEnd)` returns `end > 0`, `core.TailAudit` walks backward from `end` toward `0` in 64 KiB blocks (the local `const chunkSize = 64 << 10`), assembling complete lines across chunk boundaries with no line-length cap, matching `provider` (case-insensitive) and `failedOnly` from newest to oldest until `limit` matches are collected or offset reaches `0`, and reversing the collected slice so `fn` is still called in chronological order (it reads back only as far as the last `limit` matches reach, instead of scanning the whole log from byte 0); when `limit <= 0`, `r` cannot seek, or `Seek(0, io.SeekEnd)` fails or returns `0`, it falls back to the forward `bufio.NewReader(r)` scan, and a failed seek from the start or a `Read` error on a seekable handle (such as `EISDIR` when `audit.jsonl` is a directory in `TestMCPBridgeAuditUnreadable`) is returned immediately (`TestTailAudit` pins seekable and non-seekable readers, 100 KiB lines spanning 64 KiB boundaries, trailing and missing final newlines, `countingReadSeeker` reading `<= 64 KiB` from a 570 KiB log for `limit=2`, a failed read, and a failed seek from the start;.
49. **`mintrun version` Runs Before the Runtime and Prefers the `-X` Stamp, Then the Revision, Then the Module Version:** `version`, `-version`, and `--version` print one line, `mintrun <version> (<go version>, <GOOS>/<GOARCH>)`, before `bootRuntime`, so nothing that stops every other command (rule 45) hides the version a bug report needs. `<version>` is the `-ldflags "-X main.version=<tag>"` stamp, else the first 12 characters of `vcs.revision` plus `+dirty` when `vcs.modified` is `true`, else `Main.Version` when it is neither empty nor `(devel)`, else `dev`.
50. **`scripts/release.sh` Ships Path-Free Binaries in Owner-Free Archives, and Signs Only the macOS Binaries, Only When Asked:** It takes one `vX.Y.Z[-pre]` version (argument or `VERSION`), checked by an anchored regex before it reaches `-ldflags` or a file name, and builds darwin/arm64, darwin/amd64, linux/amd64, and linux/arm64 with `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=<version>"`. It stops when `grep -a` finds `/Users/` or `/home/` in a binary.
51. **The `mintrun watch` Dashboard URL Comes From One Function, and the Token Stays in the Fragment:** `(*WatchServer).DashboardURL(addr string) string` returns `http://<addr>/#<token>` and is the only place that URL is built, so the banner `cmd/mintrun/watch.go` prints, the macOS menu bar's parser, and `TestWatchDashboardBanner` cannot drift apart. The token rides in the URL's `#fragment`, which a browser never sends to a server, so it appears in no request line, `Host`, or `Referer`;.
52. **The Threat Model and `SECURITY.md` Claim Only What the Tests Show, and Change With Them:** `docs/threat-model.md` gives each promise its mechanism, the Go tests behind it, and its limits, and `SECURITY.md` links it and keeps a contact placeholder, never a personal address, until the maintainer fills one in. A commit that adds, widens, or narrows a promise or a limit (a new gate, approval channel, provider, or sandbox case, or a renamed test) updates the threat model in the same commit, and anything tested only against stand-ins stays under "Not yet run against real systems" until it has run against the real thing.
53. **The Semantic Screen Is Optional, Runs Last, Can Only Ask or Deny, and Treats the Request as Untrusted:** `Runtime.Screen` is nil unless `settings.json` sets `jev.mode` to `escalate` or `deny` (rule 54), so an unset or `"off"` screen costs nothing. It runs last in `decide`, after request validation, pause, purpose, `policy.json`, the env-dump guard, static, scope, permissions, installations, `blocked_commands`, TTL, and the relay verdict, so a request a deterministic rule denied costs no call and keeps its reason; it runs once per request (`checkPolicy` stores `req.Jev = d.Jev` and the second `decide` reuses it), and only when `rt.Relay == nil`: a relay client copies the server's `Jev` from the `/v1/check` and `/v1/mint` `PolicyDecision` JSON, so one request gets one verdict and a laptop's own screen never runs.
54. **`jev` Settings Are Checked Like Every Known Key, and `init jev` Stores the Key Without a Billed Test Call:** `settings.json`'s `jev` object holds `mode` (`""`, `off`, `escalate`, `deny`), `model` (empty means `jev-1.13.0`, otherwise `core.IsJevModel`), and `on_error` (`""`, `escalate`, `deny`, `pass`); an unknown `mode` or `on_error`, a model that is not `jev-...`, or a wrong type stops every command with `boot runtime: settings.json: jev.mode must be "off", "escalate" or "deny"` (and the matching `jev.on_error` and `jev.model` texts), as any other known key does (rule 45).
55. **After a Merge or Rebase, Grep Every Resolved File for Conflict Markers Before Staging:** `git add -u` stages a file whose `<<<<<<<`, `=======`, and `>>>>>>>` lines survived a resolution, and `git rebase --continue` then accepts it, so the commit can hold conflict text that no Go build ever reads: while the JEV branch was rebased onto `main`, `AGENTS.md` was staged with its rule block still wrapped in markers, and only a later scan found it.
56. **A Provider Alias `<type>@<account>` Names One Account: the Whole Alias Keys the Vault and the Policy, the Provider Sees Only Its Type, and No Rule Is Inherited:** A provider can be named `<type>@<account>` (`github@work`, `cloudflare@client-a`), so one host can hold several accounts of one provider type. A bare `<type>` is the default account, under the same vault key and `policy.json` key as before, so a single-account setup is unchanged, and `github@default` is just another account with its own key.
57. **`mintrun exec` Has No Default Permissions, and a List That Names None Is a Usage Error:** `-perms` used to default to `dns:write,workers:write`, Cloudflare's permissions, whatever the provider. An empty list is not a narrow one: `GitHubProvider.Mint` sends no `permissions`, so the token gets every permission the installation holds;.
58. **An Agent, a Relay Request, and a Shim Must Name a Permission Too:** Rule 57 closed the CLI; the callers that pick their own list refuse an empty one the same way, and a blank entry with it, because a provider may drop a blank permission and mint wider: GitHub sends no `permissions` body for an empty list, so the token holds every permission of the installation, and AWS sends no session `Policy`, so the session holds every permission of the role.
59. **A Permission or Scope a Provider Cannot Read Is Refused Before Any Request, Never Dropped, and a Glob Stands for at Least One Character:** GitHub gives an installation-token request without `permissions` every permission the installation has, so a provider that skips a request field it cannot parse widens the token instead of narrowing it. `GitHubProvider.Mint` trims each permission and refuses one that `githubPermRe` (`^[a-z0-9_]+:(read|write|admin)$`) does not match with `github permission "<trimmed>" is not <name>:<read|write|admin> (such as contents:read)`, and a scope whose part after `/` is blank with `github scope "<scope>" names no repository (use <owner>/<repo>)`, both after the static branch (rules 12, 24) and before any request, quoting neither the master nor the bearer; before the fix, `contents:`, `:read`, and `contents` were dropped, and a request holding only such pairs sent no `permissions` at all.
60. **A Live Run Prints Each Encoding on One Line and Expects the Runner's Own Outcome Words:** `Scrub` matches whole strings only (rules 3, 19), so a harness that prints a lease in an encoded form to check its redaction prints that form on one line. GitHub App installation tokens were about 390 characters on 2026-10-20;.
61. **`mintrun scan` Reads Fixed Tool Files Only, Runs Nothing, and `-add` Copies Only a Key Row Scan Found:** `scan` reads gh's `hosts.yml`, AWS `credentials` and `config`, gcloud's ADC and `legacy_credentials`, and wrangler's `default.toml`, follows a link only to a regular file of at most 1 MiB, imports no `os/exec` or `net…`, prints fixed error texts, and never prints a value or anything derived from one (rule 38). `scan -add <id>` re-runs the scan, accepts only a `key` row's id, checks it with `mintrun init`'s checks (rule 35), and stores only after a vault miss: a held key, a lookup that fails any other way, a relay, and a file vault without `MINTRUN_VAULT_KEY` are refused. It copies and never moves or edits the original, so AI apps can still read it (rule 23).
