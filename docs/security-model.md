# Defense-in-Depth Security Model

The [threat model](threat-model.md) lists what `mintrun` promises, the tests behind each promise, and where each one stops. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## 1. Declarative Policy Guardrails (`~/.mintrun/policy.json`)

Restrict which domains, repositories, roles, or permissions an AI agent may touch, cap lease TTLs, enforce a minimal child environment, or require human approval (the mintrun app or a macOS dialog, [Telegram, or Slack](approvals.md)) per provider in `~/.mintrun/policy.json`:

```json
{
  "cloudflare": {
    "allowed_scopes": ["staging.example.com", "sandbox.example.com"],
    "blocked_commands": ["delete", "r2 bucket delete", "curl"],
    "max_ttl_seconds": 300
  },
  "github": {
    "allowed_scopes": ["ninja-c9/*"],
    "allowed_permissions": ["contents:read", "contents:write", "pull_requests:write", "issues:write"],
    "blocked_commands": ["repo delete", "secret"],
    "max_ttl_seconds": 600
  },
  "gcp": {
    "allowed_permissions": ["cloud-platform.read-only", "devstorage.read_only"],
    "clean_env": true,
    "allowed_env": ["CLOUDSDK_CORE_PROJECT"]
  }
}
```

If `~/.mintrun/policy.json` exists but cannot be read (a directory, a file without read permission, a symlink to a missing file) or is malformed JSON, `mintrun` **fails closed**: it prints a warning and denies every execution until the file is fixed. Only a missing `policy.json` means no policy. `mintrun` reads the file again on every request, so a saved change applies to a running `mintrun mcp` at once.

**Pause:** while `~/.mintrun/paused` exists (the mintrun app's Pause creates it, as does `touch ~/.mintrun/paused`; anything there counts, a dangling symlink too, and removing it resumes), every new request is denied (`blocked_by: paused`) before any secret is loaded, and a request that was waiting for approval is denied once it is approved. Pause blocks new requests only: a command already running and credentials already handed out keep working until they end or expire.

**What an agent can get around:** an agent with its own shell can bypass pause and every rule here. It can run `security` itself, point `MINTRUN_HOME` at another folder (no `policy.json` or pause file there, while the Keychain items stay readable), or delete the pause file. Approval does not stop code already running as you either: it can answer on the app's socket, edit `policy.json`, or delete the pause file. See [5](#5-what-the-vault-protects-and-what-it-does-not).

**Child environment isolation:** `clean_env: true` (or any non-empty `allowed_env`) runs the command with only `PATH`, `HOME`, `TMPDIR`, `USER`, `LANG`, `TERM`, `SSL_CERT_FILE`, the `allowed_env` globs, and the lease env, so ambient host secrets such as `SSH_AUTH_SOCK` or other cloud keys never reach the child. A caller can request the same per run with `-clean-env` (CLI) or `clean_env` (MCP), but cannot switch off a policy that enables it. `MINTRUN_VAULT_KEY` is never passed to a child, even when allowlisted.

**Sandbox (macOS and Linux):** `"sandbox": true` runs every command for that provider inside the OS sandbox. On macOS it uses `/usr/bin/sandbox-exec`, with a profile that denies reads and writes in `mintrun`'s home (`~/.mintrun`: `vault.json`, `policy.json`, `audit.jsonl`) and in your Keychain folder (`~/Library/Keychains`), and denies the system services the Security framework reaches the Keychain through. On Linux it re-executes `mintrun` in new user and mount namespaces (`CLONE_NEWUSER | CLONE_NEWNS`) where `mintrun`'s home and existing keyring directories (`~/.local/share/keyrings`, `$XDG_DATA_HOME/keyrings`, `/run/user/<uid>/keyring`, `$XDG_RUNTIME_DIR/keyring`) are covered with a read-only `mode=000` `tmpfs` and existing D-Bus session bus sockets (`/run/user/<uid>/bus`, `$XDG_RUNTIME_DIR/bus`, and a `unix:path=...` socket in `DBUS_SESSION_BUS_ADDRESS`) are covered with `/dev/null`, then locks `PR_SET_SECUREBITS` (`0x2f`) and drops every capability before `exec`ing the command. Adding `"no_network": true` in `policy.json`, `-no-network` on the CLI, or `no_network: true` in MCP turns the sandbox on too (`no_network` implies `sandbox`) and also blocks network access inside the child: on macOS it adds `(deny network*)` to the `sandbox-exec` profile, and on Linux (`linux/amd64` and `linux/arm64`) the helper unshares a network namespace (`CLONE_NEWNET`, loopback left down) and installs a `seccomp-bpf` filter before `exec` that fails `socket`, `connect`, and `bind` with `EPERM` while leaving `socketpair` open. A caller can ask for `-sandbox` or `-no-network` per run, but cannot switch off a policy that enables either. When the sandbox or `no_network` is on but cannot be set up (another OS, no `sandbox-exec`, a non-filesystem `DBUS_SESSION_BUS_ADDRESS` such as `unix:abstract=...`, a host that blocks unprivileged user, mount, or network namespaces or `seccomp`, an unsupported Linux architecture for `no_network`, or a folder that cannot be resolved), the request is denied before any secret is loaded, never run without it. An approval request says `Sandbox: on` or `Sandbox: off` and `Network: blocked` or `Network: open`, and the audit entry of a sandboxed run carries `sandbox: true` (plus `no_network: true` when network egress was blocked). See [what it blocks and what it does not](#5-what-the-vault-protects-and-what-it-does-not) and [optional network isolation](#6-optional-network-isolation-no_network).

**GitHub App installations:** a credential stored as `<app_id>:<installation_id>:<private_key_pem>` or `<installation_id>:<app_jwt>` pins one installation, and `github` refuses an MCP `params.installation_id` that names a different one before any request reaches GitHub, so a pinned credential needs no policy rule. To let agents pick among several installations, store `<app_id>::<private_key_pem>` (no installation) and list the IDs they may use:

```json
{ "github": { "allowed_installations": ["12345678", "87654321"] } }
```

Once `allowed_installations` is set, every request for that provider must carry a listed `params.installation_id` (exact match, no wildcards), even if the stored credential pins one, and `mintrun_policy_check` reports the same denial. The CLI sends no `params`, so it cannot use a provider with this rule.

## 2. Anti-Exfiltration Command Filter

Even without a custom `policy.json`, `mintrun` automatically blocks trivial environment-dumping commands (`env`, `printenv`, `export`, `/proc/self/environ`) at the policy gate before any secret is unlocked or minted.

## 3. Five-Encoding Output Scrubber

Before `ExecBlind` returns `stdout`, `stderr`, `LeaseID`, or process error messages to the caller or MCP bridge, `core.Scrub()` replaces every occurrence of:
1. The **Master Secret**
2. Every injected **`Lease.Env`** value
3. Any additional provider-specified **`Lease.Redact`** and **`Lease.RevokeSecret`** tokens

across **Raw**, **Base64**, **RawBase64**, **Hex**, and **URL-encoded** representations with `[MINTRUN:REDACTED]`.

## 4. Bounded Output & Process-Group Kill

Each child stream keeps its first 4 MiB; the rest is counted and dropped, so a runaway command cannot exhaust memory. A cut stream ends with `[MINTRUN:TRUNCATED <n> bytes]`, and the result and audit entry carry `truncated: true`. A tail that could be the start of a secret variant is dropped before scrubbing, so the cut never leaves half a secret behind.

On Unix the command runs in its own process group. A timeout (5 minutes), a stop from the mintrun app, or a `SIGINT` / `SIGTERM` / `SIGHUP` to `mintrun` kills the whole group with `SIGKILL`, so no grandchild keeps running with the lease; on other systems only the command's own process is killed. A process that left the group (a daemon that called `setsid`) survives any of these. Either way the lease is revoked where its provider allows it and audited, and the entry's `revoked` says whether that worked: `cloudflare` and `github` delete their JIT tokens; `aws` and `gcp` credentials keep working until they expire; a plugin's lease ends early only when its own revoke succeeds; and a static lease is the master secret itself, never revoked. Two side effects: a command that reads the terminal directly (`/dev/tty`) is stopped by `SIGTTIN` until the timeout, and a background process the command leaves behind after a clean exit is not killed (`mintrun` stops waiting for its output 5 s after the command exits).

## 5. What the Vault Protects and What It Does Not

| Store | Protects against | Does **not** protect against |
| :--- | :--- | :--- |
| **macOS Keychain / Linux libsecret** | Other users and a copy of the disk; the secret never touches `argv`, `ps`, or shell history | Any process running as your user while the keychain is unlocked: it can run `security find-generic-password` or `secret-tool lookup` itself |
| **Encrypted file vault** (`~/.mintrun/vault.json`) | A copy of `vault.json` (backup, sync folder, lost disk) without the passphrase: AES-256-GCM with a key derived from `MINTRUN_VAULT_KEY` (PBKDF2-HMAC-SHA256, 210,000 iterations, per-vault random salt); a tampered file fails to decrypt | Any process running as your user that can read both `vault.json` and the passphrase (from a shell profile, an MCP config file, or, on Linux, `mintrun`'s environment), a keylogger, or offline guessing of a weak passphrase |

The blind command is such a process. `mintrun` never passes `MINTRUN_VAULT_KEY` to it, which stops accidental exposure (an `env` dump, a debug log), but a command written to steal secrets can still query the keystore, or read `vault.json` and look for the passphrase (a shell profile, an MCP config file, and on Linux `mintrun`'s own environment through `/proc/$PPID/environ`). On macOS 27.0, `ps -E` and `sysctl` showed another process's arguments but not its environment in our test; older releases are untested. `mintrun` keeps raw secrets out of the agent's context and transcripts; unless the [sandbox](#1-declarative-policy-guardrails-mintrunpolicyjson) is on, it does not confine the command it runs. Block what an agent must not run with `blocked_commands`, and use `require_approval` (the mintrun app or a macOS dialog, Telegram, or Slack) to see each command before it runs.

**What the sandbox blocks.** `TestSandboxHidesHome` runs real commands under `sandbox-exec` on macOS 27.0 and under user and mount namespaces on Linux (Ubuntu 24.04, kernel 6.17): a sandboxed command cannot read, list, or write `mintrun`'s home or the keystore folder (`~/Library/Keychains` on macOS, `~/.local/share/keyrings` on Linux) by its path, read `mintrun`'s home through a symlink (or in other letter case on macOS), or on Linux read `/proc/$PPID/environ`, while its exit code and environment (where the lease travels) come through unchanged. On Linux the test passed both as an unprivileged user and as `root` (`uid=0`), and a command whose `cwd` is inside a hidden directory fails to start (`exit 126`, `permission denied`). In a manual check on macOS 27.0, `security find-generic-password` also failed inside the sandbox (exit 44, as for a missing item). `TestSandboxHidesKeychainItem`, opt-in because it stores a throwaway item in your login Keychain and then deletes it, shows the same for a real item on macOS 27.0: without the sandbox, a command read the item with `security` and read the login Keychain file; inside it, `security` exited 44 and reading the file was denied. On Linux, `TestSandboxHidesSecretTool` starts a throwaway `dbus-daemon` and `gnome-keyring-daemon`, stores a throwaway item with `secret-tool`, and shows that without the sandbox a command read the item over `DBUS_SESSION_BUS_ADDRESS` and over `$XDG_RUNTIME_DIR/bus`, read `login.keyring`, and listed `$XDG_RUNTIME_DIR/keyring`, while inside it all four failed and the host lookup still worked afterwards. What it does **not** do:

- **Block the network unless `no_network` is on.** With `sandbox` alone, the same test fetches a local URL with `curl` from inside the sandbox, and in the manual check `curl`, `git`, and `python3` reached HTTPS sites, so a command can still send its lease credential anywhere unless `no_network` is also enabled (see [6](#6-optional-network-isolation-no_network)).
- **Block a hard link made beforehand.** `sandbox-exec` matches paths and the Linux sandbox mounts over directories, so a hard link to a file in `mintrun`'s home, made beforehand in another folder, stays readable on both OSes (the test shows this).
- **Confine other processes.** A sandboxed command could ask a process outside the sandbox to act for it (an Apple Event to Terminal, `launchctl`, X11, `ssh` to this machine). None of that is blocked, and none of it has been tested. The agent itself is not confined either: an agent with its own shell can query the keystore without `mintrun`.
- **Keep keystore logins or D-Bus session services working.** On macOS 27.0, a tool that reads its own login from the Keychain (`gh auth status` when `gh` stores its token in the Keychain, or `git` with the `osxkeychain` helper) fails inside the sandbox (`gh auth status` exits 1 with `The token in default is invalid` unless a `GH_TOKEN` / `GITHUB_TOKEN` lease is injected), and on Linux the D-Bus session bus socket is covered with `/dev/null`, so any tool that uses libsecret or the session bus fails inside; use the lease `mintrun` injects instead.
- **Work on other OSes, or when the OS blocks the sandbox.** On every OS but macOS and Linux, when `DBUS_SESSION_BUS_ADDRESS` is not a single absolute `unix:path=...` socket, or on a Linux host that blocks unprivileged user namespaces (for example, Ubuntu 24.04's `kernel.apparmor_restrict_unprivileged_userns=1` or `user.max_user_namespaces=0`), a sandboxed request is denied at the policy gate before any secret is loaded. Apple marks `sandbox-exec` deprecated; it works on macOS 27.0, and if a later release drops it, sandboxed requests are denied, not run.

## 6. Optional Network Isolation (`no_network`)

By default, a blind command keeps network access—inside the sandbox too—so it can talk to cloud APIs (`gh`, `aws`, `gcloud`, `wrangler`), and could also send its lease credential elsewhere (`curl`, `nc`, any script interpreter). When a command only needs the injected secret for local work (offline signing, rendering templates, verifying a local bundle) and must not open any network or local socket connection, set `"no_network": true` in `policy.json`, pass `-no-network` to `mintrun exec`, or pass `"no_network": true` to MCP `mintrun_exec`:

- **Implies `sandbox: true` and only tightens.** Turning `no_network` on turns the OS sandbox on too (`~/.mintrun` and the keystore stay hidden), and a caller can add `-no-network` per run without ever loosening a policy that requires it. Because `mintrun` itself mints and revokes the lease in the parent process, JIT token minting and revocation still reach the cloud API normally; only the child process has its network blocked. Conversely, a child CLI that itself needs to reach a remote API (`wrangler`, `gh`, `aws`, `gcloud`, `curl`) will fail when `no_network` is on.
- **macOS (`sandbox-exec`):** adds `(deny network*)` to the profile. `TestSandboxBlocksNetwork` (`-tags integration`) verified on macOS 27.0 that TCP `connect`, UDP `WriteTo`, Unix domain socket `connect` on the filesystem, `net.Resolver` DNS lookup, and `/usr/bin/dns-sd -t 1 -G v4 localhost` (which reaches `mDNSResponder` over Mach IPC) all fail inside `ExecBlind` when `no_network` is on and succeed when it is off, while writing a local file outside `~/.mintrun`, passing bytes over an anonymous `socketpair(AF_UNIX)`, and reading the lease env still succeed.
- **Linux (`CLONE_NEWNET` + `seccomp-bpf` on `linux/amd64` and `linux/arm64`):** the sandbox helper both unshares a new network namespace (`CLONE_NEWNET`, with `lo` left down so even inherited IP sockets have no route) and, right before `exec`, installs a 9-instruction `seccomp-bpf` filter (`SECCOMP_SET_MODE_FILTER`) that checks `seccomp_data.arch` and fails `socket`, `connect`, and `bind` with `EPERM` (blocking host-filesystem and abstract `AF_UNIX` sockets too, while leaving `socketpair(AF_UNIX)` open). Both `CLONE_NEWNET` and the `seccomp-bpf` install run during the `decide` dry-run probe, and any Linux architecture other than `amd64` or `arm64` is rejected in `linuxSandboxArgv`, so a host that blocks either fails closed (`blocked_by: sandbox`) before any secret is loaded. `TestSandboxBlocksNetwork` passed on Ubuntu 24.04 (`linux/arm64`, kernel 6.17) both as an unprivileged user and as `root`; under `--platform linux/amd64` user-mode emulation on an `arm64` kernel, `prctl(PR_SET_SECCOMP)` returns `EINVAL` and the `decide` dry-run probe fails closed as expected (`policy denied: sandbox is on, but the Linux sandbox cannot be used (invalid argument)`), while a native `linux/amd64` integration run awaits a real x86-64 Linux kernel.

## 7. Team Relay (`mintrun relay`)

When a team wants one central server to hold the master secrets, `policy.json`, and the server-side audit log while developer laptops hold only short-lived leases, run `mintrun relay`:

```bash
# On the relay server: enroll a laptop (token is shown once; only its SHA-256 hex is stored in ~/.mintrun/relay/devices.json)
./mintrun relay device add laptop-alice
./mintrun relay device list
./mintrun relay device remove laptop-alice

# On the relay server: serve /v1/check, /v1/mint, and /v1/revoke over TLS 1.3 (prints the #sha256=<spki_hex> pin on startup)
./mintrun relay serve -listen 0.0.0.0:8443 -cert /path/to/cert.pem -key /path/to/key.pem

# On the client laptop: store the one-time device token in the local vault (or export MINTRUN_RELAY_TOKEN)
./mintrun secret set relay
export MINTRUN_RELAY="https://relay.internal:8443#sha256=<64-hex-spki-pin>"

# Run via the relay (or pass -relay explicitly; MCP mintrun_exec and mintrun_policy_check use MINTRUN_RELAY automatically)
./mintrun exec -provider cloudflare -scope example.com -perms dns:write,workers:write -- npx wrangler deploy
```

- **Device authentication, constant-time verification & per-device rate/lease caps:** `mintrun relay device add <name>` (`[A-Za-z0-9._-]{1,64}`, other than `.` and `..`) generates a one-time `mr_dev_<rand.Text()>` bearer token and stores only its lowercase SHA-256 hex digest in `<home>/relay/devices.json` (`0600`). Every request to `POST /v1/check`, `POST /v1/mint`, and `POST /v1/revoke` compares the bearer token's SHA-256 against all enrolled devices with `subtle.ConstantTimeCompare` without early exit. A missing, unreadable, symlink-dangling, or malformed `devices.json` fails closed without leaking the server's filesystem path. Each authenticated device has its own token-bucket rate limit on `/v1/check` and `/v1/mint` (`300` requests/min, burst `60`; returns `HTTP 429 Too Many Requests` with `Retry-After: 1` when exceeded without affecting other devices, which the client reports as `relay rate limited (429: rate limit exceeded)`). `/v1/revoke` spends no token, so a device that hits the limit can still end its leases instead of leaving them live until they expire. Each device also has a concurrent active-lease cap (`32` unrevoked leases per device on `/v1/mint`, counting mints still in flight, so parallel requests cannot pass it; returns `HTTP 429` with `Retry-After: 1` before minting, which the client reports as `relay lease cap reached (429: too many active leases for device)`, while that device can still call `/v1/revoke` to free a slot, and a denied or failed mint frees its slot at once). `mintrun relay serve` always uses these defaults; no flag changes them.
- **TLS 1.3 + mandatory SPKI SHA-256 pinning:** the relay URL must be `https://<host>[:port]#sha256=<64-hex>` (plain HTTP, userinfo, query strings, or a missing pin are refused). The client enforces TLS 1.3 (`MinVersion` and `MaxVersion`), checks the leaf certificate's `NotBefore`/`NotAfter` validity window, and compares `sha256(cert.RawSubjectPublicKeyInfo)` against the pinned digest in constant time.
- **Fail-closed policy, approval, and static-mode refusal:** `POST /v1/check` runs `CheckPolicy` on the server, and the client tightens its local verdict with the server's (`TTLSeconds`, `ApprovalRequired`, `CleanEnv`, `Sandbox`, `NoNetwork`). If the relay server cannot be reached, rejects the device token (`401`), rate-limits the device (`429`), or sends a reply that does not decode, the check fails closed (`blocked_by: "relay"`) with a reason that says which. Neither the client nor the server allows picking `vault`, setting `timeout_seconds`, or requesting `static` (non-JIT) mode over the relay, even when `allow_static: true` is in `policy.json`. On the server, human approval runs over Telegram and Slack (`FirstApproval(TelegramApproval(rt), SlackApproval(rt))`) and includes a quoted `Device: "<name>"` line ahead of `Purpose:` and `Client:`.
- **Server-side revocation & two-entry audit trail:** `Lease.RevokeSecret` stays on the server and is never sent to the laptop. `POST /v1/mint` writes an initial server audit entry with `outcome: "minted"`, `via: "relay"`, and `device: "<name>"`, and starts an in-memory expiry timer. When the laptop finishes and calls `POST /v1/revoke` (which answers a lease of another device as it answers an unknown one, with `404 unknown lease`), the server revokes the lease with the provider and writes the final audit entry (`done`, `failed`, `stopped`, `interrupted`, or `timed_out`). If the laptop crashes or goes offline before calling `/v1/revoke`, the server revokes the lease at expiry, or at once when the relay server shuts down, and writes the second audit entry with `outcome: "unreported"` and `exit_code: -1`.
- **What the relay protects and what it does not:**
  - The master secret and `Lease.RevokeSecret` never leave the relay server; if a provider returns a non-ephemeral lease or a lease whose `Env`, `Redact`, or `RevokeSecret` contains the master secret, the server revokes it best-effort and refuses to send it. `MINTRUN_RELAY_TOKEN` is stripped from the blind child environment in every mode alongside `MINTRUN_VAULT_KEY`, and scrubbed from `RelayClient` errors.
  - The ephemeral lease itself reaches the laptop so the local child command can use it: the command, and any other process running as that user on the laptop, can use that lease until it is revoked or expires.
  - The server sees only the command `argv`, `cwd`, and `purpose` the laptop claims it will run, so `blocked_commands` and the command shown in the approval prompt are only as honest as the client device. The boundaries a compromised laptop cannot bypass are the ones enforced at mint time on the server: provider, scope, permissions, TTL, installations, human approval per mint, and per-device token revocation (`mintrun relay device remove <name>`).
  - Active leases are held in server memory; if the relay server process crashes and restarts while a lease is in flight, its in-memory revoke handle is lost and that lease remains valid until its provider TTL expires.

## 8. Semantic Screen (optional, through TypeSafe AI)

Policy, `blocked_commands`, and the sandbox decide from deterministic rules. An optional semantic screen adds a second, probabilistic opinion: one call to TypeSafe AI's Jev `System One` model that reads the request and returns a risk verdict which can only ask a human or deny, never allow. It is **off by default** and stays off until `settings.json` names it:

```json
{
  "jev": {
    "mode": "escalate",
    "model": "jev-1.13.0",
    "on_error": "escalate"
  }
}
```

- **It can only add a check.** `mode: "escalate"` turns a high-risk verdict into a human approval; `mode: "deny"` lets it deny outright. It runs last in the policy gate, so a request a deterministic rule already denied costs no API call and keeps its reason, and nothing the screen returns can allow a request that policy, the sandbox, or a missing approval denied. An unset or `"off"` mode builds no screen at all; a `jev` block with an unknown `mode`, `on_error`, or a model that is not a `jev-...` ID stops every command with `settings.json: jev...` rather than being ignored, like any other known setting.
- **What it is asked.** Seven calibrated yes/no questions (credential exfiltration, phrased twice so a denial needs both, destructive work, a command that does not match its stated purpose, an injected instruction, a vague request, scope creep) and one 0-3 severity score with its confidence. The provider's rule can move the thresholds: `jev.ask_above` (default `0.35`), `jev.deny_above` (default `0.85`), `jev.severity_deny` (default `3`). A denial needs both exfiltration questions at or above `deny_above`, or a severity at or above `severity_deny` with confidence of at least `0.6`; any other flagged label, or an unsure severity, asks a human. `vague` is shown to the approver but never asks on its own, because `mintrun` has no `require_purpose`.
- **What leaves the machine.** One screening per request: an HTTPS `POST` to `api.typesafe.ai`, holding the same request fields the approval text shows (provider, scope, permissions, params, `argv`, working directory, purpose, client name, device name, and the sandbox and network flags), the provider's rule (`allowed_scopes`, `allowed_permissions`, `blocked_commands`, `require_approval`), and the questions. Never the master secret, a lease, a child's output, or an audit line, and a home path in those fields is shortened to `~` or `$MINTRUN_HOME`. The screen reads the default vault's `jev` key on first use and never the vault a request names. Store the key with `mintrun init jev`; `mintrun doctor` reports `screen: off`, or the mode with the model and `on_error`, and warns when the model is an alias rather than a version, since TypeSafe can move an alias without notice.
- **What the vendor promises.** TypeSafe's legal page says it does not train on user data. Zero data retention is offered only to enterprise customers through sales, neither a retention period nor SOC 2 or GDPR is published, and we have not read their DPA, MCA, or privacy policy. Treat the screen as sending your command lines to a third party: name a model version instead of an alias, and an operator who needs zero retention should get it in writing before turning the screen on.
- **A failed screen is a policy decision.** `on_error` says what a timeout (5 s per call, an 8 s budget across retries, with doubling backoff on `429` and `529`), an unreachable host, or a reply that does not match the schema means: `escalate` (the default) asks a human, `deny` denies, and `pass` drops the verdict. `pass` is an operator's explicit choice to keep running when TypeSafe is down; it weakens the screen and never the deterministic gate. Every failure is audited with `jev_error`, scrubbed.
- **Where the verdict shows.** The approval prompt gains a `Risk:` line under `Network:`, in the macOS app, the dialog, Telegram, Slack, and `mintrun watch`, with a closed vocabulary (`not screened`, `low`, `medium`, `high`, `unknown`, plus the labels, severity, and model); a verdict that carries free text can write none of it there. `audit.jsonl` keeps `jev_risk`, `jev_labels`, `jev_severity`, `jev_model`, `jev_ms`, and `jev_error`, `mintrun_audit` shows them with `jev_error` redacted, and the app socket carries `"jev"` on the `approve` line.
- **`mintrun_policy_check` is an oracle.** The tool runs the same gate, so it runs the screen, and an agent can call it repeatedly to learn which wording scores low. A probabilistic answer is not a policy: keep `require_approval` for anything that matters, keep `blocked_commands` narrow, and treat the screen as one more signal rather than the boundary.
- **Behind the relay, only the server sends.** A relayed request skips the laptop's screen entirely and copies the server's verdict, so a laptop's `settings.json` cannot weaken the server's screening, and the server's `minted` audit entry carries the `jev_*` fields. The laptop never holds the key.
- **Cost and latency.** Each screened request is a billed TypeSafe call and adds a round trip (typically a fraction of a second). A request that a deterministic rule denies costs nothing, and a request whose verdict nobody acts on still costs a call.
