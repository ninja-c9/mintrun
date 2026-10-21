# Threat Model

`mintrun` runs a command for an AI agent. It mints a short-lived credential (a lease) from a master secret the agent never handles, hands the lease to the command as environment variables, scrubs known secrets from what it returns, and can ask you before any secret loads. This page lists what `mintrun` promises, the tests behind each promise, and where each promise stops. It claims only what those tests show: anything they do not cover is listed as a limit, or under [Not yet run against real systems](#not-yet-run-against-real-systems).

To report a way around a promise, see [SECURITY.md](../SECURITY.md).

Test names below are Go tests in this repository. `go test ./...` runs against local stand-ins (stub programs and `httptest` servers) and never calls a real provider, keystore, or chat service. `TestSandboxHidesHome`, `TestSandboxHidesKeychainItem`, `TestSandboxHidesSecretTool`, `TestSandboxBlocksNetwork`, `TestKeychainVaultRealKeychain`, and `TestScanRealHome` run only with `-tags integration` and use the real sandbox, Keychain, keyring, or home folder; some run only on macOS or only on Linux.

## What it protects

- **Master secrets:** the long-lived credentials that `mintrun secret set` and `mintrun init` store in the macOS Keychain, libsecret, the file vault (`~/.mintrun/vault.json`), 1Password, or a vault plugin. The approval settings `approval-telegram` and `approval-slack` are stored the same way.
- **The vault passphrase and the relay token:** `MINTRUN_VAULT_KEY`, which unlocks the file vault, and `MINTRUN_RELAY_TOKEN`, which a laptop sends to a relay server.
- **Leases:** the credential minted for one command, which should end when the command ends or soon after.
- **`mintrun`'s state** under `~/.mintrun` (or `MINTRUN_HOME`): `policy.json`, `settings.json`, the `paused` file, `audit.jsonl`, `app.sock`, and on a relay server `relay/devices.json`.

## Who is involved

| Actor | Trust |
| :--- | :--- |
| You, the operator | Trusted. You store the masters, write `policy.json`, and answer approvals. |
| The AI agent | Untrusted input. Over MCP it picks the provider, scope, permissions, params, command, working directory, TTL, and purpose, and can turn on approval, the sandbox, `no_network`, and `clean_env` (each only adds a check). Its client name is a self-reported label. It cannot pick the vault or a time limit. |
| The command (the child) | Runs as your user. Untrusted, and not confined unless the sandbox is on. |
| Other programs running as your user | Not confined by `mintrun`. See [Code already running as you](#code-already-running-as-you). |
| Other users on the machine | Kept out of `~/.mintrun`, which `mintrun` creates with mode `0700`, and out of the keystore by the OS, except through the `mintrun watch` dashboard (see [Approval](#approval)). |
| Providers (GitHub, Cloudflare, AWS, GCP) | Trusted to mint, scope, and revoke leases as their APIs say. |
| Telegram and Slack | See the text of every approval request they carry. |
| Plugins | Trusted code. A provider plugin receives the master. |
| A relay server | Trusted. It holds the masters for its devices. |
| A relay device | Trusted only with the leases it is handed. |

Trust boundaries:

1. **Agent to `mintrun`:** MCP over stdio, or the CLI. The policy gate runs before any vault opens.
2. **`mintrun` to the command:** the lease goes in as environment variables; output comes back scrubbed and capped.
3. **`mintrun` to providers:** HTTPS calls that mint and revoke.
4. **`mintrun` to approvers:** the macOS app over `~/.mintrun/app.sock`, the macOS dialog, Telegram, Slack, and the `mintrun watch` dashboard.
5. **A laptop to a relay server:** TLS 1.3 pinned to the server's public key, plus a device token.

## What it promises

The rule numbers point to `<learned_rules>` in [AGENTS.md](../AGENTS.md) and the full unabridged specification in [docs/learned-rules.md](learned-rules.md), which records each mechanism and the mutants its tests catch.

| Promise | Mechanism | Evidence | Limits |
| :--- | :--- | :--- | :--- |
| The agent never handles a master. | `mintrun` reads the master into its own memory, mints a lease, and gives the command only the lease. The agent cannot pick the vault (rule 16). `MINTRUN_VAULT_KEY` and `MINTRUN_RELAY_TOKEN` never reach the command, even with `allowed_env: ["*"]` (rule 11). | `TestExecBlindCleanEnv`, `TestMCPBridgeExecCleanEnv`, `TestMCPBridgeRefusesVault`, `TestMintLeaseAndRelayClient` | Unless the sandbox is on, the command can read the master from the keystore ([The command runs as you](#the-command-runs-as-you)). A static lease is the master itself. A provider plugin receives the master. |
| Masters at rest stay in a keystore or encrypted. | The Keychain or libsecret by default. The file vault uses AES-256-GCM with a key derived by PBKDF2 from `MINTRUN_VAULT_KEY` and a per-vault salt, and refuses a file without both (rule 9). Secrets reach `security` and `secret-tool` on stdin, never in argv (rules 14, 18). | `TestKeychainVaultMacOSSecurity`, `TestKeychainVaultLinuxSecretTool`, `TestFileVaultPassphraseRequiredPhase45PRC`, `TestFileVaultSymlink` | Any program running as you can read a Keychain item `mintrun` stored, without a prompt (rule 23). The file vault is only as safe as the place you keep `MINTRUN_VAULT_KEY`. |
| Leases are narrow and short, and revoked where the provider allows. | `policy.json` allowlists scopes, permissions, and GitHub installations, and caps the TTL (`max_ttl_seconds`); a lease asks for 600 s by default. `mintrun exec` has no default permissions: a run without `-perms`, or whose `-perms` names none, stops with the usage line before anything is minted or audited, because an empty list asks GitHub and AWS for everything the installation or role holds (rule 57). An agent's `mintrun_exec` or `mintrun_policy_check`, and a relay request, that names no permission or a blank one is denied as `invalid_request` (exit 126, audited, before the pause), and a shim in `auto` mode left with none stops with exit 126 naming the `shims/config.json` key to set, before anything is minted (rule 58). Cloudflare tokens and GitHub App installation tokens are deleted when the command ends, and the audit entry records `revoked` (rules 13, 21, 27). A GitHub permission that is not `<name>:<read|write|admin>`, a GitHub scope with no repository, and a blank Cloudflare permission are refused before any request, never dropped: GitHub gives a token request without `permissions` everything the installation has (rule 59). | `TestCloudflareJITMintBlindExecAndAutoRevoke`, `TestCloudflareProviderComprehensive`, `TestGitHubProviderAndJWTSigningComprehensive`, `TestGitHubPermissionsFailClosed`, `TestAWSProviderComprehensive`, `TestAWSSigV4FixedVector`, `TestGCPProviderPhase5`, `TestCheckPolicyMatchesExecBlind`, `TestCLIExecRequiresPerms`, `TestMCPBridgeRefusesEmptyPermissions`, `TestMCPExecSchema`, `TestCLIShim` | AWS and GCP leases cannot be revoked early ([Revocation](#revocation)). With no rule for a provider, the agent picks the scope and permissions ([Without a policy](#without-a-policy)). A Cloudflare permission name picks the first catalog group whose name holds it, so a short name can pick a group you did not mean. Only GitHub App installation tokens, from a master pinned to its installation, have been minted and revoked through a real API ([Not yet run against real systems](#not-yet-run-against-real-systems)); the rest is tested against stand-ins only. |
| Known secrets are scrubbed from everything `mintrun` returns or logs. | The master and every lease value are replaced in raw, Base64, unpadded Base64, lowercase hex, and URL-encoded form in stdout, stderr, errors, and `audit.jsonl` (rules 3, 8, 12). A stream cut at 4 MiB never ends inside a secret (rule 19). | `TestBuiltinGitHubJITEncodingScrubAndHITLApproval`, `TestMintFailureAndLeakyPluginLeaseAreScrubbed`, `TestGitHubLeaseIDIsOpaqueAndTokenNeverReachesAuditOrMCP`, `TestExecBlindOutputCap`, `TestPluginInvalidJSONNeverQuotesStdout` | Whole strings in those five forms only, so a command can print the lease reversed or in another encoding and the agent reads it ([The scrubber matches whole strings](#the-scrubber-matches-whole-strings)). |
| The policy gate fails closed. | The gate runs before any vault opens and reads `policy.json` on every request. A file that exists but cannot be read or parsed denies every request, the `paused` file denies every request, and a sandbox that cannot be set up denies before the vault opens. After an approval the gate runs again (rules 16, 36, 43). A `*` in an allowlist stands for at least one character, so `contents:*` never admits `contents:` and `owner/*` never admits `owner/` (rule 59). | `TestCheckPolicyMatchesExecBlind`, `TestGitHubPermissionsFailClosed`, `TestPolicyReload`, `TestPauseRecheckAfterApproval`, `TestPolicyFailClosedPhase45PRB`, `TestCLIExecPaused` | `policy.json` and `paused` are local files any program running as you can change. No file, or no rule for a provider, means no rules for it ([Without a policy](#without-a-policy)). |
| Each account has its own secret and its own rule. | A provider can be named `<type>@<account>`, such as `github@work`: the whole name is the vault key and the `policy.json` key, and a bare `github` is the default account. The gate refuses a name in any other form before a vault opens, and a `policy.json` key in any other form makes the file malformed, which denies every request. The provider mints from that account's secret and sees only its type, while the lease, the approval text, and the audit entry name the account. `mintrun exec` needs `-provider` (rule 56). | `TestExecBlindProviderAlias`, `TestCheckPolicyMatchesExecBlind`, `TestRegistryAndExternalVaultAndRemoteInstall`, `TestApprovalHints`, `TestSecretNotFoundHint`, `TestTailAudit`, `TestMCPAuditProviderAlias`, `TestRelayEndToEnd`, `TestCLIExecRequiresProvider`, `TestCLIInit`, `TestCLIDoctor`, `TestCLIShim` | No rule is inherited: an account with no rule of its own has no rules, whatever the bare type's rule says ([Without a policy](#without-a-policy)). The agent picks the account by naming it, so it can ask for any account whose secret is stored. |
| You approve before any secret loads, when approval is on. | `-approve`, `MINTRUN_APPROVE=1`, the agent's `approve: true`, or a `require_approval` rule asks the macOS app (or, when the app is not running, the macOS dialog) and, when they are set up, Telegram and Slack, all at once. The first answer wins; a failure, or no answer within the deadline (10 minutes unless `settings.json` sets less), denies. The request text quotes every agent field and starts with the sandbox and network lines, and Deny is the dialog's default button (rules 4, 31, 34, 42). | `TestOSApproval`, `TestFirstApproval`, `TestApprovalTimeout`, `TestTelegramApproval`, `TestSlackApproval`, `TestAppApproval`, `TestWatchServer` | Off unless asked for. Telegram and Slack see the request text, and any program running as you can answer on `app.sock` ([Approval](#approval)). |
| A sandboxed command cannot read `mintrun`'s home or the keystore. | `sandbox-exec` on macOS, and user and mount namespaces on Linux, hide `~/.mintrun` and the keystore folders; on macOS the profile also denies the Security services. `no_network` adds `(deny network*)` on macOS, and a network namespace plus a `seccomp-bpf` filter on Linux. A request or a rule can turn either on but never off (rules 43, 46). | `TestSandboxHidesHome`, `TestSandboxHidesKeychainItem`, `TestSandboxHidesSecretTool`, `TestSandboxBlocksNetwork` (real sandbox on macOS 27.0, and on Ubuntu 24.04 on linux/arm64, kernel 6.17), `TestExecBlindSandbox`, `TestExecBlindLinuxSandbox`, `TestLinuxSandboxSysProcAttrAndHelper`, `TestCLIExecSandbox` | Off unless asked for, and it covers only the command, never `mintrun` or the agent ([Sandbox and no_network](#sandbox-and-no_network)). |
| A runaway command is bounded. | Each output stream keeps 4 MiB, and the command is killed after 5 minutes. A timeout, a stop from the app or `mintrun watch`, or Ctrl-C, `SIGTERM`, or `SIGHUP` to `mintrun` kills the command's whole process group, and the lease is still revoked and audited (rules 19, 20). | `TestExecBlindOutputCap`, `TestExecBlindKillsProcessGroup`, `TestExecBlindStop`, `TestKillProcessGroupFork`, `TestCLIExecAppStop` | [Process cleanup](#process-cleanup). |
| Every run is audited. | Every exit of a run writes one scrubbed entry with its verdict to `~/.mintrun/audit.jsonl`; a relay server writes two per lease, one when it hands the lease out and one when the run ends or the lease expires. `mintrun_audit` shows an agent the verdicts only, never text an agent wrote (rules 8, 16, 47). | `TestMCPBridgeGovernanceTools`, `TestMCPBridgeExecUnreadable`, `TestMintLeaseAndRelayClient` | [Audit log](#audit-log). |
| A plugin cannot replace a built-in or install unverified. | A plugin cannot take a built-in's name or escape its folder. A remote install needs an `https://` URL and a `#sha256=` digest you supply, and a bare name installs the copy built into `mintrun` (rules 10, 33). | `TestRegistryAndExternalVaultAndRemoteInstall`, `TestPluginInstallCatalog` | Plugins run as you, and a provider plugin receives the master ([Plugins](#plugins)). |
| A relay keeps the masters on one server. | TLS 1.3 pinned to the SHA-256 of the server's public key; device tokens stored only as SHA-256 hashes; policy, approval, and minting on the server; static mode refused; a per-device rate limit and lease cap (rule 47). | `TestRelayURLAndCertPin`, `TestRelayDevices`, `TestRelayEndToEnd`, `TestRelayRateLimitAndLeaseCap`, `TestRelayClientCutOffReply`, `TestMintLeaseAndRelayClient`, `TestCLIRelay` | Tested in one process only ([Relay](#relay)). |
| Works with the CLIs you already use. | The lease goes in the variables those CLIs read: `GH_TOKEN` and `GITHUB_TOKEN`; `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`; `CLOUDFLARE_API_TOKEN`; `CLOUDSDK_AUTH_ACCESS_TOKEN`. | `TestCloudflareJITMintBlindExecAndAutoRevoke`, `TestAWSProviderComprehensive`, `TestGCPProviderPhase5` | The command holds a working credential while the lease lasts and can send it anywhere unless `no_network` is on. |
| `mintrun scan` only reads, and `scan -add` copies only what it found. | `scan` reads fixed files: gh's `hosts.yml`, AWS `credentials` and `config`, gcloud's application default credentials and `legacy_credentials`, and wrangler's `default.toml`, each where the tool's own location variable puts it. It follows a link only to a regular file of at most 1 MiB, runs no program, opens no connection, prints fixed error texts, and prints only names: an id, the file's place under `~/`, an AWS profile name, or a service account's address, never a value or anything derived from one (rule 38). `scan -add <id>` runs the same scan and accepts only the id of a `key` row, so a caller never names a path. It checks the key with `mintrun init`'s checks (rule 35) and refuses a relay, a file vault without `MINTRUN_VAULT_KEY`, a key the vault holds, and a vault it cannot read (rule 61). | `TestScanEmptyHome`, `TestScanFindsEachSource`, `TestScanFileErrors`, `TestScanFIFO`, `TestScanAWS`, `TestScanGCP`, `TestScanGitHub`, `TestScanWrangler`, `TestScanImports`, `TestScanAddAWS`, `TestScanAddGCP`, `TestScanAddRefusals`, `TestScanRealHome` | Every byte of those files, secrets included, passes through `mintrun`'s memory, and `-add` leaves the original where it was ([Scan](#scan)). |
| No third-party code. | `go.mod` names no dependency (rule 1). `scripts/release.sh` builds with `-trimpath`, refuses a binary that holds a local home path, and writes `SHA256SUMS`. | `go.mod`, `scripts/release.sh` | `SHA256SUMS` is not signed, and releases ship no SBOM ([Releases](#releases)). |

## Where the promises stop

### The command runs as you

The command runs as your user, with your user's rights (rule 23). Unless the sandbox is on, it can:

- read the master from the keystore itself: any program running as you can run `security find-generic-password` on macOS, or `secret-tool lookup` on Linux, and read an item `mintrun` stored, without a prompt;
- read `~/.mintrun/vault.json`, and look for `MINTRUN_VAULT_KEY` wherever you keep it, such as a shell profile;
- on Linux, read `mintrun`'s environment, `MINTRUN_VAULT_KEY` included, from `/proc/$PPID/environ`. On macOS 27.0, `ps -E` and `sysctl KERN_PROCARGS2` showed the command none of its parent's environment; older macOS releases and a debugger attach are untested.

Keeping `MINTRUN_VAULT_KEY` out of the command's environment stops an accident, not a hostile command. `mintrun` keeps raw secrets out of the agent's context and transcripts; without the sandbox, it does not stop a command it runs from reaching them.

### Code already running as you

`mintrun` governs only the requests that go through it. An agent with its own shell tool, or any other program running as you, needs no `mintrun` to reach your secrets: it can read the keystore, edit or delete `policy.json`, `settings.json`, and the `paused` file, point `MINTRUN_HOME` elsewhere, edit `audit.jsonl`, and answer approvals on `app.sock`.

The shims (`mintrun shim install`) send a habitual `gh` or `aws` to `mintrun`, but an absolute path, a changed `PATH`, or another tool gets past them: they change habits and are not a boundary (rule 39). For `mintrun` to be an agent's only way to a credential, the agent itself must run without a general shell or inside its own confinement.

### Revocation

- **Cloudflare and GitHub:** a Cloudflare token or a GitHub App installation token is deleted when the command ends, and the audit entry says `revoked: true` when the delete succeeded. GitHub sets an installation token's lifetime itself; the lease TTL does not shorten it. In a live run, a revoked installation token got HTTP 401 at the first request after the command ended.
- **AWS:** STS credentials cannot be revoked. They live until they expire, at least 900 s and at most 43,200 s after minting, and the lease reports `revoked: false` (rule 21).
- **GCP:** `mintrun` asks Google to revoke the token, but Google does not revoke service-account access tokens early and fixes their lifetime at up to 1 hour, so the lease reports `revoked: false`. Neither `-ttl` nor `max_ttl_seconds` shortens it (rule 13).
- **Static leases** are the master itself and are never revoked.
- **Plugin leases** end early only if the plugin's revoke works.
- **A killed `mintrun`:** after `SIGKILL` or a crash, nothing is revoked or audited, the command keeps running, and each lease lives until it expires. A relay server revokes such a lease when it expires and records it as `unreported` (rule 47).

### The scrubber matches whole strings

- It replaces a secret only in raw, Base64, unpadded Base64, lowercase hex, and URL-encoded form. Uppercase hex, base64url, base32, a reversed or split string, part of a secret, or an encrypted copy gets through. So does a string an encoder wraps across lines: `xxd -p` writes 60 hex characters per line by default, and in a live run a GitHub installation token of about 390 characters printed with `xxd -p -c 256` came out on two lines, neither of them redacted. A command the agent writes can print the lease in any of those forms, and the agent reads it; an AWS or GCP lease read that way works until it expires.
- It skips a secret shorter than 4 bytes.
- It covers only what comes back through `mintrun`. A command can send a lease over the network unless `no_network` is on, and can write it to a file the agent reads later.
- It knows only the secrets `mintrun` holds. Other variables in your environment reach the command, and its output, unless `clean_env` is on.
- The env-dump filter and `blocked_commands` match substrings of the command line. `python3 -c 'import os; print(os.environ)'` gets past the filter: the lease values in its output are still scrubbed, but nothing else is.

### Without a policy

With no `policy.json`, or no rule for a provider (an account such as `github@work` with no rule of its own counts, whatever the `github` rule says):

- the agent picks the scope and permissions, though it must name at least one permission;
- the lease asks for 600 s;
- nothing asks you first unless `-approve`, `MINTRUN_APPROVE=1`, or the agent's own `approve: true` asks for approval;
- the sandbox is off and the network open unless the request turns them on;
- the command gets your whole environment, minus `MINTRUN_VAULT_KEY` and `MINTRUN_RELAY_TOKEN`, unless `clean_env` is on.

What still applies: the `paused` file, the env-dump filter, the refusal of static mode, the refusal of an agent's `vault` and `timeout_seconds`, the purpose check, and the provider's own refusal of a malformed GitHub permission or scope or a blank Cloudflare permission. `mintrun init policy` writes a starting `policy.json`.

### Approval

- Telegram and Slack carry the request text: whether the sandbox is on and the network blocked, the provider, vault, scope, permissions, params, command, working directory, and the agent's purpose and client name. It stays in the chat. No secret `mintrun` holds is in it, but a secret or a user name typed into the command or the working directory is.
- `Purpose:` and `Client:` are the agent's claims: any process can send any client name (rule 41).
- Any program running as you can listen on `~/.mintrun/app.sock` and answer approvals (rule 42).
- `mintrun watch` serves a dashboard on a loopback TCP port (rule 48). The URL it prints ends in a `#token`, which `(*WatchServer).DashboardURL` builds and `TestWatchDashboardBanner` follows end to end; a browser never sends a URL fragment, so the token appears in no request line, `Host`, or `Referer`. `ServeHTTP` first refuses any `Host` that is not the loopback address and port it listens on, with `{"error":"forbidden Host header"}`, so a page that points its own host name at `127.0.0.1` cannot reach it, and then requires the token in `X-Mintrun-Token` on every `/api/` request, compared in constant time, so `GET /api/state` — which returns the pending approval texts and the last 20 audit entries — and `POST /api/decide`, `/api/stop`, and `/api/pause` all refuse a missing or wrong one; every mutating `POST` also keeps the `X-Mintrun-Watch: 1` header that a cross-site page cannot set. `GET /` is tokenless because a browser page load cannot send a header, and the page it serves holds no state: the dashboard reads the token from its own fragment. What stays: any local user or program that reads the printed URL, the terminal, or `mintrun`'s memory has the token, and the menu bar's "open dashboard" opens the page without the fragment, so it shows the refusal rather than the dashboard. Run `mintrun watch` only on a machine you do not share, or with `-http ''` to turn the dashboard off.
- The channels are tested against stand-ins only: the dialog against a stub `osascript`, Telegram and Slack against `httptest` servers, and the app against a fake socket server.

### Sandbox and no_network

- Both are off unless a rule, the CLI, or the agent turns them on.
- The sandbox confines only the command. `mintrun` reads the vault, mints, and revokes outside it, and the agent is not confined at all.
- Without `no_network`, the command can reach the network.
- A hard link to a file in a hidden folder, made before the run, stays readable.
- A process outside the sandbox that the command reaches (through an Apple Event, `launchctl`, X11, or `ssh`) is neither blocked nor tested.
- Tools that read logins from the Keychain or over the D-Bus session bus fail inside it.
- It runs on macOS and Linux only. On any other system, on a Linux host that blocks unprivileged user namespaces, with a D-Bus address other than a single `unix:path=`, and for `no_network` on a Linux architecture other than amd64 and arm64, `mintrun` denies the request instead of running the command unconfined.
- Apple marks `sandbox-exec` deprecated; it works on macOS 27.0.
- The real-sandbox tests ran on macOS 27.0 and on Ubuntu 24.04 (linux/arm64, kernel 6.17). They have not run on a native linux/amd64 host.

### Process cleanup

- A process that leaves the command's process group (with `setsid`, say) is not killed.
- After the command exits on its own, a background process it started is not killed; `mintrun` waits up to 5 s for the output pipes and moves on.
- On macOS, a fork by another member of the group, or one slower than 10 ms, can survive the kill.
- Outside Unix, only the command's own process is killed, not its children.
- A command that reads `/dev/tty` is stopped by `SIGTTIN`.
- If `mintrun` is killed with `SIGKILL`, the command keeps running.

### Audit log

- `~/.mintrun/audit.jsonl` is a local JSON Lines file with mode `0600`. It is not signed or chained, and you, or any program running as you, can edit or delete it.
- It records the agent's purpose and client name as the agent stated them.
- A run cut short by `SIGKILL` or a crash leaves no entry.
- A relay server keeps its own log; a laptop's log shows only its own runs.

### Plugins

- A plugin runs as you, with your rights.
- A provider plugin receives the master on every mint and revoke, and a vault plugin sees every secret it stores.
- The example plugins (`bitwarden`, `vercel`, `postgres-jit`) are tested against stub programs and a stand-in API only (rule 32).

### Relay

- The lease reaches the laptop, where any program running as you can use it while it lasts.
- The server sees only what the laptop says it will run: the command, working directory, and purpose are claims. What holds is what the server checks when it mints.
- The server keeps active leases in memory. If it crashes, it cannot revoke them, and each lives until it expires.
- The relay is tested only within one process, never between two machines.

### Scan

- `scan` reads each file whole to find its names, so the file's secrets pass through `mintrun`'s memory, as they would through any program running as you that reads the file. Only `-add` keeps a value, and only to store it.
- `-add` copies a key and never moves or edits the original. An agent with a shell, or any program running as you, can still read it there. For `mintrun` to hold the only copy, remove the original yourself.
- A sign-in (`gh auth login`, `gcloud auth login`, AWS SSO, `wrangler login`) is a personal login `mintrun` cannot mint a short-lived credential from, so `-add` refuses it and points to `mintrun init`.
- It reads only the files above. It skips keys held in environment variables (`GH_TOKEN`, `AWS_ACCESS_KEY_ID`, `CLOUDFLARE_API_TOKEN`, `GOOGLE_APPLICATION_CREDENTIALS`), gh's token in the Keychain, and every other tool.
- The macOS app, started from the Dock, does not see variables your shell profile sets, so a `GH_CONFIG_DIR`, `AWS_SHARED_CREDENTIALS_FILE`, or `CLOUDSDK_CONFIG` set there moves what a shell's `mintrun scan` reads but not what the app's does.
- A label is an AWS profile name or a service account's address, which can name a person, a client, or a project. Any program running as you can run `mintrun scan` and read them.

### Releases

- With `SIGN_IDENTITY` set, `scripts/release.sh` signs the macOS binaries with a Developer ID (hardened runtime, secure timestamp), and with `NOTARY_PROFILE` set too, it has Apple notarize each one and stops unless the result is `Accepted`. A bare binary cannot be stapled, so Gatekeeper checks the notarization online. The Linux binaries are not signed, `SHA256SUMS` is not signed, and releases ship no SBOM.
- `SHA256SUMS` comes from the same place as the archives, so it catches a damaged download, not a replaced release.
- There is no public CI: the checks run through `scripts/verify.sh` on a maintainer's machine.
- Builds are not checked to be reproducible across machines.

## Not yet run against real systems

These are tested against stand-ins only so far:

- the Cloudflare, AWS, and GCP providers against the real APIs (AWS request signing matches AWS's published test vector);
- the GitHub provider with an unpinned `<app_id>::<pem>` or bare JWT master, and a token narrowed below what its App holds. The one live App run, recorded in [checks.md](../checks.md), minted and revoked installation tokens for one repository through an account alias over the CLI and MCP, with a master pinned to its installation and an App holding only Contents read on that repository;
- the client names that real AI apps send over MCP;
- `mintrun apps connect`, `mintrun apps disconnect`, and `mintrun init mcp` against real AI apps;
- `mintrun scan` against the files real `aws` and `gcloud` write, including whether current gcloud still writes `legacy_credentials`, and wrangler's Linux location; `scan -add` against any real file. On macOS 27.0, `TestScanRealHome` and `mintrun scan` found a real gh sign-in and a wrangler login at `~/Library/Preferences/.wrangler/config/default.toml` with no error row (2026-10-21, [checks.md](../checks.md));
- the macOS app end to end: approve, stop, and pause over `app.sock`, and a click on **Add to mintrun** in its sign-in window (its model ran `scan -add` against a file vault, but no click reached the button and the Keychain was not used);
- the macOS dialog closing at the approval deadline;
- Telegram and Slack approvals with real bots;
- the 1Password vault, the `bitwarden` and `vercel` plugins with real accounts, and `postgres-jit` against a real PostgreSQL server;
- the real-sandbox tests on a native linux/amd64 host;
- `mintrun` on Windows and FreeBSD;
- a relay between two machines.

## Out of scope

`mintrun` does not defend against:

- root or an administrator on the machine;
- a compromised kernel or OS;
- malware already running as you, beyond what the limits above describe;
- someone with physical access to an unlocked machine;
- a compromised provider, Telegram, or Slack.

## Reporting

See [SECURITY.md](../SECURITY.md).
