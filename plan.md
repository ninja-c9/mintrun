# `mintrun` Execution Plan & Backlog

> **Harness Spec:** [AGENTS.md](AGENTS.md) · **Latest Release:** `v0.15.0` · **Constraints:** 100% Go `1.24.0` standard library (`0` external dependencies), `> 90%` verified statement coverage measured without build tags.

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
   go test -tags integration -count=1 -v -run '^TestScanRealHome$' ./cmd/mintrun               # real home, read-only, logs counts only
   ```

---

## 2. Completed Workstreams (A–AJ)

> Full step-by-step specifications and verification commands for completed Workstreams A–AJ (`v0.4.0`–`v0.15.0`) are archived in [docs/archive/plan-history.md](docs/archive/plan-history.md).

## 3. Deferred Backlog (Next Actionable Items)

1. **`no_network` Child Sandbox Option (completed in `v0.12.0`, Workstream AC, rule 46):** `"no_network": true` in `policy.json`, CLI `-no-network`, and MCP `no_network: true` imply `sandbox: true` and block network egress inside the child (`(deny network*)` on macOS; `CLONE_NEWNET` + 9-instruction `seccomp-bpf` filter on `linux/amd64` and `linux/arm64`). Verified via `TestSandboxBlocksNetwork` on macOS 27.0 and Ubuntu 24.04 (`linux/arm64`, kernel 6.17); `linux/amd64` live integration run awaits an x86-64 Linux host.
2. **Linux Host Verification:** moved to the §5 live-check runbook, item 4 (`-approve` with Telegram and Slack as the only channels; `secret-tool` is already verified).
3. **Live Runs: Telegram, 1Password, Bitwarden & Vercel:** moved to the §5 live-check runbook, items 2–3 (each run with the user's own throwaway bot or account; `checks.md` §3 turns `pass` only on that run's output).
4. **Live Slack Approval Run:** moved to the §5 live-check runbook, item 2 (the user's own throwaway workspace and app).
5. **GCP `token_uri` From the Service-Account Key:**
   - Deferred: only keys outside the default Google universe carry a different `token_uri`, and honoring it also means sending revocation to that universe. Add it when such a key is in use.
6. **Team Relay (`mintrun relay`, completed in `v0.13.0`, Workstream AE, rule 47):** TLS 1.3 SPKI-pinned relay server (`mintrun relay serve`), SHA-256 device token auth (`mintrun relay device add|remove|list`), client (`exec -relay`, `MINTRUN_RELAY`, `MINTRUN_RELAY_TOKEN`), and MCP support; see [§5](docs/archive/plan-history.md#5-roadmap-to-v0120--v0130-approved-2026-10-18) and [checks.md](checks.md).

---

## 9. Workstream AK — Multi-Account Provider Aliases (`type@account`, `v0.16.0`, 2026-10-19)

> **Breaking:** `mintrun exec -provider` loses its `cloudflare` default. Nothing else changes for a single-account user.

**Model.** A provider string is an identity: `<type>` (the default account) or `<type>@<account>`. The identity keys the vault secret, the `policy.json` rule, the audit `provider`, the approval text, the relay request, and the `PolicyDecision`; only the type picks code: `Registry.Provider`, `approvalOwnHosts`, and the `MintRequest` (and lease) a provider sees. There is no rule inheritance: `github@work` is governed by a `"github@work"` rule or, without one, like any provider without a rule. `<account>` is 1 to 64 bytes of `[A-Za-z0-9._-]`, not `.` or `..` (the relay device-name charset, now one helper).

**Not built (on purpose):** rule inheritance, auto-picking an alias for a bare request, a credential table or per-account config, per-directory shim accounts, keystore items namespaced by home, and any change to "no rule means allow".

### AK-1 — Core Gate, Registry, Lease
- **Files:** `internal/core/runner.go`, `internal/core/plugin.go`, `internal/builtin/cloudflare.go`, `internal/builtin/relay.go`, `internal/core/core_test.go`.
- **Deliverables:**
  1. `[SERIAL]` `core.SplitProvider` and `core.ValidName` (relay device names call it too).
  2. `[SERIAL]` `decide` refuses a malformed alias right after the empty-provider check: `invalid_request`, audited with exit 126, before the pause, the same reason through `mintrun_policy_check`.
  3. `[SERIAL]` `Registry.Provider`: the exact name, else the type before the first `@`; the not-found error quotes the name as given. `Register` and `safePluginName` refuse `@`.
  4. `[SERIAL]` `acquireLease`: the vault key stays the alias, `Mint` and `Revoke` see the type, the returned lease carries the alias; the built-ins stop hard-coding `Lease.Provider`.
  5. `[SERIAL]` `approvalHints` looks up `approvalOwnHosts` by type; `TailAudit`: a bare type matches its aliases, an alias matches only itself.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestRegistryAndExternalVaultAndRemoteInstall|TestExecBlindProviderAlias|TestTailAudit|TestApprovalHints' ./internal/core
  ```

### AK-2 — MCP
- **Files:** `internal/builtin/mcp.go`, `internal/builtin/builtin_test.go`.
- **Deliverables:** `[SERIAL]` `shortLabel` keeps `@`; the `provider` schema description reads `type[@account]` with one example.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestMCPExecSchema|TestMCPBridgeGovernanceTools|TestMCPAuditProviderAlias' ./internal/builtin
  ```

### AK-3 — CLI `exec` and `audit`
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`.
- **Deliverables:** `[SERIAL]` a missing `-provider` is a usage error (`fatal`, exit 1, nothing audited); usage text names `<type>[@<account>]`; `audit -provider github` also lists `github@<account>` (it hands the filter to `core.TailAudit`, which `TestTailAudit` pins).
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIExecRequiresProvider' ./cmd/mintrun
  ```

### AK-4 — `init` and the Missing-Secret Hint
- **Files:** `cmd/mintrun/setup.go`, `internal/builtin/keychain.go`, their tests.
- **Deliverables:**
  1. `[SERIAL]` `github`, `aws`, `gcp`, `cloudflare` ask `Account name (Enter for the default): ` after the passphrase check and before the replace prompt, which names the alias; `-account <name>` skips the question.
  2. `[SERIAL]` `setupHint`: `(run mintrun init <type> -account <name>)` for an alias of an init-step type, `(run mintrun secret set <alias>)` otherwise.
  3. `[SERIAL]` `init policy` also suggests a rule for each alias the shim config names; it still never changes an existing `policy.json`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIInit|TestSecretNotFoundHint' ./...
  ```

### AK-5 — `doctor` and Shims
- **Files:** `cmd/mintrun/setup.go`, `cmd/mintrun/shim.go`, their tests.
- **Deliverables:**
  1. `[SERIAL]` `doctor` prints a vault row for every `policy.json` key and shim `provider` holding `@` (`ok`, or `-` with the vault's hint), read-only.
  2. `[SERIAL]` `shimEntry.Provider`: validated by `loadShimConfig` (fail closed), sent by `runShim`, printed in the block hint, set by `shim install -provider` (numbered choice when `policy.json` holds several accounts of the tool's type), and checked by `doctorShims`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIDoctor|TestCLIShim' ./cmd/mintrun
  ```

### AK-6 — Relay Alias
- **Deliverables:** `[SERIAL]` a relay request for an alias mints from the server's alias secret, and both server entries and the lease name the alias.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestRelayEndToEnd|TestMintLeaseAndRelayClient' ./...
  ```

### AK-7 — Mutants
- **Deliverables:** `[SERIAL]` on a copy of the tree, each mutant compiled first (`go test -run '^$'`) and failing a named test; the count goes in [checks.md](checks.md).

### AK-8 — Docs and Rules
- **Files:** `README.md`, `docs/threat-model.md`, `AGENTS.md`.
- **Deliverables:** `[SERIAL]` README "Multiple accounts" and "Breaking changes in v0.16.0"; the threat model's policy-gate row; AGENTS.md rule 56 and the `shortLabel` charset in rules 16 and 41.
- **Verification:** the rule-52 citation script passes on the tree and fails on each planted fault (fake test name, bad anchor, missing file, untracked file).

### AK-9 — Acceptance
- **Deliverables:** `[SERIAL]` `scripts/verify.sh`; bidi, conflict-marker, and leak scans with planted controls; `./mintrun` rebuilt; a manual run in a throwaway `HOME` and `MINTRUN_HOME` with `MINTRUN_FILE_VAULT=1`; commits on the branch only (no push, tag, or merge).
- **Verification:**
  ```bash
  scripts/verify.sh
  ```

## 10. Workstream AL — `mintrun exec` Requires `-perms` (`v0.16.0`, 2026-10-19)

> **Breaking, under the same `v0.16.0` note as AK:** `mintrun exec -perms` loses its `dns:write,workers:write` default, which was Cloudflare's but applied to every provider.

**Choice.** Require `-perms`, as AK made `-provider` required, rather than a default per provider. An empty list widens: GitHub then sends no `permissions` body (the token gets every permission the installation holds) and AWS no session `Policy` (every permission of the role), so no default is safe for every provider, and a per-provider table would have to be kept in step with every plugin. `-perms static` stays the static opt-in (rule 24).

**Not changed (on purpose):** `GitHubProvider.Mint` (another session owns the malformed-permission fix), the MCP `mintrun_exec` path, and the shims, which set their own permissions.

### AL-1 — CLI `exec`
- **Files:** `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`.
- **Deliverables:** `[SERIAL]` `-perms` defaults to `""`; the list is split and trimmed first, and an empty list (`-perms ""`, `-perms " , ,"`, or none) is a usage error before `configureRelay` and `ExecBlind`, so nothing is minted or audited; the usage line names `-perms <perm,...|static>`; every test that relied on the default passes `-perms`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIExecRequiresPerms|TestCLIExecRequiresProvider|TestCLIRelay|TestCLISubcommandsEndToEnd' ./cmd/mintrun
  ```

### AL-2 — Mutants
- **Deliverables:** `[SERIAL]` on a copy of the tree, each mutant compiled first (`go test -run '^$'`) and failing a named test; the count goes in [checks.md](checks.md) and rule 57.

### AL-3 — Docs and Rules
- **Files:** `README.md`, `examples/plugins/README.md`, `docs/threat-model.md`, `AGENTS.md`.
- **Deliverables:** `[SERIAL]` the README's `v0.16.0` note and every `mintrun exec` example name `-perms`; the plugin examples pass a placeholder their plugin ignores (`deploy`, `login`); the threat model's lease row; rule 56's usage text and a new rule 57.
- **Verification:** the rule-52 citation script passes on the tree and fails on each planted fault.

### AL-4 — Acceptance
- **Deliverables:** `[SERIAL]` `scripts/verify.sh`; bidi, conflict-marker, and leak scans with planted controls; `./mintrun` rebuilt; `./mintrun exec -provider github -- true` in a throwaway `MINTRUN_HOME` with `MINTRUN_FILE_VAULT=1`; one commit on the session branch (no push, tag, or merge).
- **Verification:**
  ```bash
  scripts/verify.sh
  ```

## 11. Workstream AM — Agents, the Relay, and the Shims Must Name a Permission (`v0.16.0`, 2026-10-19)

> **Breaking, under the same `v0.16.0` note as AK and AL:** an agent's `mintrun_exec` or `mintrun_policy_check` that omits `permissions`, and an `aws`, `vercel`, or `psql` shim in `auto` mode with no permissions configured, used to mint with an empty list.

**Choice.** Refuse where each caller picks its list. The gate (`decide`) refuses an agent's or a relay request's empty or blank list as `invalid_request`, under the guard of the vault and timeout refusals, so `mintrun_policy_check` and `ExecBlind` agree (rule 16) and the denial is audited before the pause. The shim refuses its own list before it looks up the real binary, naming the `shims/config.json` key to set. A global check in `decide` would have refused every direct Go caller too, and `CheckPolicy` is not where the CLI refuses (rule 57). No built-in provider or example plugin needs an empty list.

**Not changed (on purpose):** `GitHubProvider.Mint` (another session owns the malformed-permission fix), and Cloudflare's own fallback for an empty list, now reachable only from a Go caller of `ExecBlind`.

### AM-1 — Gate and Schema
- **Files:** `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/mcp.go`, `internal/builtin/builtin_test.go`, `cmd/mintrun/main_test.go`.
- **Deliverables:** `[SERIAL]` `decide` denies a `FromAgent` or relay request whose list is empty or holds a blank entry, right after `ValidProvider`; the MCP schema marks `permissions` required; every agent or relay request in the tests names a permission.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCheckPolicyMatchesExecBlind|TestMintLeaseAndRelayClient' ./internal/core
  go test -count=1 -v -run 'TestMCPBridgeRefusesEmptyPermissions|TestMCPExecSchema' ./internal/builtin
  ```

### AM-2 — Shim
- **Files:** `cmd/mintrun/shim.go`, `cmd/mintrun/shim_test.go`.
- **Deliverables:** `[SERIAL]` `runShim` in `auto` mode exits 126 with the config key to set when the inferred list is empty or holds a blank entry, before the binary lookup and `ExecBlind`.
- **Verification:**
  ```bash
  go test -count=1 -v -run 'TestCLIShim' ./cmd/mintrun
  ```

### AM-3 — Mutants, Docs, Acceptance
- **Deliverables:** `[SERIAL]` mutants on a copy, each compiled first; rule 58 and the edits to rules 16, 39, and 57; the threat model's lease row and "Without a policy"; README's shim, MCP, and `v0.16.0` notes; the rule-52 citation check; bidi, conflict-marker, and leak scans with planted controls; `./mintrun` rebuilt; one commit on the session branch (no push, tag, or merge).
- **Verification:**
  ```bash
  scripts/verify.sh
  ```

## 12. Workstream AN — `mintrun scan` (Read-Only) and `scan -add` (2026-10-21)

> Gives the macOS app's onboarding scan real data: for each provider, whether a sign-in the user already has is a **key** mintrun can copy, or a **signin** (a personal login mintrun cannot mint short-lived credentials from). Out of scope: the Swift side of the app and the design board (follow-ups).

**Command.** `mintrun scan` prints only a JSON array, one row per finding or error, like `mintrun apps status` (rule 44), and exits 1 when a row carries `error` (the JSON is still printed). A row is `{"id","provider","kind","where","label","temporary","error"}`: `kind` is `key` or `signin`, `where` is `~/…` inside the home, `label` holds only a user-chosen AWS profile name or a service account's `client_email` and must match `^[A-Za-z0-9._@+-]{1,128}$`, and `temporary` means an `aws_session_token` field is present (a field's presence, never a value; rule 38). Rows sort github, aws, gcp, cloudflare, then by `id`. No MCP tool: an agent has no need to know where sign-ins live and must not trigger `-add`.

**Sources** (an empty variable counts as unset; a variable is honored only when it moves the tool's own config):
- **gh:** `GH_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gh`, else `~/.config/gh`; `hosts.yml`'s top-level key names only (`^[A-Za-z0-9.-]+:\s*$`); `github.com:` gives `github:gh`, `signin`. No `security` lookup, no token.
- **AWS:** `AWS_SHARED_CREDENTIALS_FILE` or `~/.aws/credentials`, and `AWS_CONFIG_FILE` or `~/.aws/config`, read by an INI parser that keeps key names only (`[x]`, `[default]`, `[profile x]`; `[sso-session …]` and `[services …]` ignored), merged by profile. `aws_access_key_id` gives `aws:<profile>`, `key`; `sso_session` or `sso_start_url` gives `signin`; `role_arn`, `credential_process`, or `web_identity_token_file` alone gives no row; a profile name the label charset refuses gives an error row without the name.
- **gcp:** `CLOUDSDK_CONFIG` or `~/.config/gcloud`: `application_default_credentials.json` and `legacy_credentials/*/adc.json` (at most 20 directories), reading `type` and `client_email`. `service_account` gives `gcp:adc` or `gcp:gcloud:<client_email>`, `key`; `authorized_user` gives `gcp:gcloud-login`, `signin`; other types are skipped. Never `credentials.db` or `GOOGLE_APPLICATION_CREDENTIALS` (it can point into Documents).
- **wrangler:** `~/.wrangler/config/default.toml`, then on darwin `~/Library/Preferences/.wrangler/config/default.toml`, on linux `${XDG_CONFIG_HOME:-~/.config}/.wrangler/config/default.toml`; an `oauth_token =` line gives `cloudflare:wrangler`, `signin`. The candidates are a function of (home, GOOS, env) so both lists are tested on any host.

**Invariants (rule 61).** `scan.go` imports no `os/exec` and no `net…`. A file is found through `os.Lstat` (only not-exist means none, rule 36), followed through a link only to a regular file, and read through `io.LimitReader` up to 1 MiB; a dangling link, directory, FIFO, socket, unreadable file, or larger file is an error row. Error texts are fixed (`not valid JSON`, `line 7 is not key = value`): a parser error is never wrapped, because `json.SyntaxError` can quote a byte. No value, nor anything derived from one, is printed (rule 38); values are read only by `-add`. No static-mode hint for a personal sign-in (rule 24).

**`scan -add <id> [-account <name>]`.** Re-runs the same discovery and looks the id up, so a caller never names a path; a `signin` id is refused with `mintrun init <type>`, an unknown id with `unknown id`. It reads the profile's `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token`, or the whole GCP file, validates with the checks `mintrun init` uses (split out in AN-1, same messages), and stores under `<type>` or `<type>@<account>` (`core.ValidProvider`, rule 56). It refuses a key the vault already holds (hint: `-account <name>` or `mintrun init <type>`), a file vault without `MINTRUN_VAULT_KEY` (the `init` message), and a configured relay. Then `SetSecret` and one JSON row `{"id","key","vault"}`. It copies and never moves or edits the original.

### AN-1 — Shared AWS and GCP Checks
- **Files:** `cmd/mintrun/setup.go`.
- **Deliverables:** `[PARALLEL]` with AN-2. The AWS master builder and GCP key-file check move out of `wizard.aws` and `wizard.gcp` into functions `-add` can call, with the same error texts.
- **Verification:** the same `--- PASS` set as before the split.
  ```bash
  go test -count=1 -v -run '^TestCLIInit' ./cmd/mintrun
  ```

### AN-2 — `mintrun scan`
- **Files:** `cmd/mintrun/scan.go`, `cmd/mintrun/scan_test.go`, `cmd/mintrun/main.go` (dispatch, usage).
- **Deliverables:** `[PARALLEL]` with AN-1. The four sources, the row order, and the fixed errors. Hermetic tests (rule 22) with `t.TempDir()` homes and the location variables cleared: per source missing, data, link to a file, dangling link, directory, FIFO (`unix`), over 1 MiB with a canary, `chmod 000` (skipped as root), and malformed with the canary as the bad byte; AWS merge, SSO, `role_arn` only, temporary, bad name, and variable override; gcp's three types and two sorted legacy directories; gh's precedence and a GHE-only file; wrangler's darwin and linux candidates. A canary scan of stdout and stderr (raw, base64 Std and Raw, hex, URL) with a positive control; stubs `gh`, `aws`, `gcloud`, `wrangler`, `security`, `sqlite3` first on `PATH` leave no marker (with a positive control); a `go/parser` test that `scan.go` imports no `os/exec` and no `net…`.
- **Verification:** every new test shows `--- PASS` (rule 15).
  ```bash
  go test -count=1 -v -run '^TestScan' ./cmd/mintrun
  ```

### AN-3 — `scan -add`
- **Files:** `cmd/mintrun/scan.go`, `cmd/mintrun/scan_test.go`.
- **Deliverables:** `[SERIAL]` after AN-1 and AN-2. File-vault tests through `runMainWithArgs`: the stored AWS (`id:secret[:token]`) and GCP (whole file) masters, `-account`, refusals of an existing key, a `signin` id, an unknown id, and a relay; a 39-character AWS secret gets `init`'s message without the value; the original keeps its SHA-256 and mtime.
- **Verification:**
  ```bash
  go test -count=1 -v -run '^TestScanAdd' ./cmd/mintrun
  ```

### AN-4 — Docs and Rule 61
- **Files:** `docs/threat-model.md`, `README.md`, `AGENTS.md`, `docs/learned-rules.md`.
- **Deliverables:** `[PARALLEL]` with AN-3. A Scan section in the threat model (promises with their tests; limits: file bytes, secrets included, pass through mintrun's memory; `-add` copies, so AI apps can still read the original; the app does not see the shell's variables; wrangler and gcloud stay under "Not yet run against real systems"); one README command line; rule 61 (≤ 3 sentences) with its mechanism in `docs/learned-rules.md`.
- **Verification:** a path and host leak scan (rule 3) with a planted control; every test name the docs cite exists.

### AN-5 — Acceptance
- **Deliverables:** `[SERIAL]` `scripts/verify.sh`, `go test -race`, `GOOS=linux` and `GOOS=windows go build ./...`, `./mintrun` rebuilt, and `HOME=<fixture> ./mintrun scan` on a fixture home. No commit, push, or tag without the user.
- **Verification:**
  ```bash
  scripts/verify.sh
  ```

### AN-6 — Real Machine (Ask First)
- **Deliverables:** `[SERIAL]`, only with the user's yes. `scan_integration_test.go` (`//go:build integration`, `TestScanRealHome`) checks the real home gives valid JSON with no error row and logs only counts per provider and kind; confirm the wrangler location on macOS and whether current gcloud still writes `legacy_credentials`, then move what ran out of "Not yet run against real systems".
- **Verification:**
  ```bash
  go test -tags integration -count=1 -v -run '^TestScanRealHome$' ./cmd/mintrun
  ```
