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

1. **Zero External Dependencies:** `go.mod` must only declare the module path and Go toolchain version (`go 1.24.0`). All cryptographic and network protocols (RS256 JWT, AWS SigV4, AES-256-GCM, SHA-256 pinning, MCP JSON-RPC 2.0) must be implemented using 100% Go standard library packages.
2. **No GitHub Actions CI (`.github/workflows`):** This repository does not use GitHub Actions. Never create or re-introduce a `.github/` directory.
3. **Zero-Secret & Zero-PII Leak Invariant:**
   - Every credential handled at runtime (Master Secret, `Lease.Env`, `Lease.Redact`) must pass through `core.Scrub()` (covering Raw, Base64, RawBase64, Hex, and URL-encoded forms) before reaching `stdout`, `stderr`, or `~/.mintrun/audit.jsonl`.
   - Never commit local absolute filesystem paths (such as user home directories or workspace paths), hostnames, device identifiers, or real tokens in source code, tests, comments, or documentation (`README.md`, `AGENTS.md`). Always use relative paths and `-trimpath` when building binaries.
4. **Native OS HITL Dialog Formatting:** When invoking `/usr/bin/osascript` for human-in-the-loop approval (`defaultOSApproval`), never embed raw unescaped newlines inside AppleScript string literals—always format the prompt payload with `%q` in `fmt.Sprintf`.
5. **Verified Statement Coverage (`> 90%`):** Never report estimated coverage numbers. Always execute `go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out` and remove temporary `coverage.out` artifacts before committing.
6. **Keep `./mintrun` Binary Synchronized:** After modifying any file under `cmd/` or `internal/`, rebuild with `go build -trimpath -o mintrun ./cmd/mintrun` so local CLI and MCP server executions run the latest code.
7. **Lease IDs Are Public Handles, Never Secrets:** `Lease.ID` is returned to agents (`ExecResult.LeaseID`, MCP) and written to `audit.jsonl`, so providers must set it to an opaque non-secret handle (e.g. `gh-inst-<installation_id>-<unix>`). A credential needed only by `Revoke` goes in `Lease.RevokeSecret` (`json:"-"`, never serialized); the runner still scrubs `lease.ID` against all known secrets as defense in depth.
8. **Scrub Every `ExecBlind` Exit Path, Not Just Successful Output:** Errors (especially `provider.Mint` failures, which can echo plugin stderr or API response bodies), `LeaseID`, and the audit `command`/`error` fields must all pass through `Scrub()` with the master secret plus every lease secret. Return scrubbed error text with `%s`, never wrap a raw error that may contain a secret with `%w`.
9. **File Vault Requires a Passphrase, Derived With a Salted KDF:** The AES-256-GCM fallback vault (`internal/builtin/keychain.go`, the at-rest store on non-macOS hosts) must never derive its key from the filesystem path or any other guessable value. Require a non-empty `MINTRUN_VAULT_KEY` and derive the key with `crypto/pbkdf2.Key(sha256.New, pass, salt, …)` using a per-vault random salt persisted in `vault.json` (`__salt__`). `readMap` must reject any file lacking both `__aes256gcm__` and `__salt__` (legacy plaintext and foreign formats are fail-closed, not silently trusted). This is a breaking on-disk format: an existing `vault.json` must be removed and re-created with `mintrun secret set`. Write the vault atomically (temp file + `Sync` + `os.Rename`) and always check `crypto/rand.Read` errors for both salt and nonce.
10. **Plugins Cannot Shadow Built-ins, Escape Their Directory, or Install Unverified:** `Registry.Register` must reject a non-builtin plugin whose name matches an existing built-in vault/provider/bridge. Any plugin name used as a path segment must pass `safePluginName` (single segment, no `.`/`..`/separators) on both install and remove. Remote install must require an out-of-band `#sha256=<hex>` digest (a bundle's self-declared digest is attacker-controlled and proves nothing) and an `https://` URL, with a loopback-only carve-out for plaintext (still integrity-checked by the mandatory digest); a remote bundle is always forced `Builtin: false`.
11. **Child Env Never Carries the Vault Passphrase; Clean Mode Only Tightens:** `ExecBlind` builds the child environment with `childEnv`. `MINTRUN_VAULT_KEY` is never inherited, even when `allowed_env` matches it. Clean mode (`ExecRequest.CleanEnv` **or** policy `clean_env` **or** a non-empty `allowed_env`) keeps only `PATH`, `HOME`, `TMPDIR`, `USER`, `LANG`, `TERM`, `SSL_CERT_FILE`, the `allowed_env` globs, and `Lease.Env`. A request (CLI `-clean-env`, MCP `clean_env`) may tighten policy but never loosen it.
12. **Providers Scrub Their Own Derived Secrets; Static Mode Is Explicit and Key-Free:** The runner knows the master secret only as one whole string, so a provider that derives sub-secrets (a signed JWT assertion, a parsed private key from a JSON master) must scrub them from its own error text (e.g. `GCPProvider.postForm`) and list them in `Lease.Redact`. Static mode must be requested explicitly (`static` permission or `mode=static`) so the `allow_static` policy gate applies, and must refuse long-lived key material (GCP refuses a service-account JSON or PEM).
13. **GCP Revocation Is Best-Effort; Revocation Tokens Go in the Body:** Google does not revoke service-account access tokens server-side and fixes their lifetime (≤1h), so `revoked=false` is expected and neither `-ttl` nor `max_ttl_seconds` can shorten a GCP lease; never document otherwise. Send revocation tokens in the POST body, never in a URL query.
14. **Secrets Reach Helper CLIs on stdin, From Absolutely Resolved Binaries:** Pass secrets to helper CLIs (e.g. `secret-tool store`) on stdin, never argv (visible in `ps`). Use an `exec.LookPath` result only when `err == nil`, because Go returns a relative-path match together with `exec.ErrDot`. `mintrun secret set` reads piped stdin whole, so multi-line secrets (service-account JSON, PEM) are never truncated to their first line, and a failed stdin read is fatal so a partial read never overwrites a stored secret.
15. **Run Each Step's Verification Check Verbatim and Confirm It Selects the New Tests:** A `go test -run` regex in `plan.md` that matches no test still exits `ok`, so a renamed or differently named test silently drops out of the check (for example, `TestKeychainLinux` does not match `TestKeychainVaultLinuxSecretTool`). Run each step check with `-v` and confirm every new test appears as `--- PASS`; fix the regex or the test name when it does not.
16. **MCP Governance Tools Are Read-Only Views of the Real Gate:** `mintrun_policy_check` must call `core.(*Runtime).CheckPolicy`, the same function `ExecBlind` enforces through `checkPolicy`, and must never open a vault, mint, exec, call `ApprovalFunc`, or write `audit.jsonl`. Add every new gate rule to `CheckPolicy`, never to `ExecBlind` alone (`TestCheckPolicyMatchesExecBlind` pins each denial reason to the `ExecBlind` error). Request validation (empty `provider`/`command`) lives there too, so those failures are audited with exit 126 like any denial. `mintrun_audit` hands agents only `argv[0]` plus `[MINTRUN:REDACTED]`: a policy-denied entry keeps the raw argv (no secret is loaded yet to scrub against) and a secret typed into argv is unknown to `Scrub`, so arguments never reach an agent. The on-disk log keeps the full argv for the operator.
17. **Format Only This Checkout:** `.claude/worktrees/` can hold other sessions' git worktrees, and `gofmt` walks into dot-directories (unlike `go vet ./...`, which skips them), so `gofmt -s -w .` can rewrite another session's files. Run `gofmt -s -l .` first; if it lists anything under `.claude/`, format the repo's own packages only (`gofmt -s -w cmd internal`).
