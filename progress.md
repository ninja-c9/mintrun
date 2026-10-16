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
| **`v0.9.0` — Keystore Cleanup, Example Plugins & Phone Approval** | ✅ Done | A `secret set` that falls back to the file vault after a failed Keychain or libsecret store removes the older keystore item for the key, which used to shadow the new secret on read, or fails with an error saying that item still wins; a successful Keychain or libsecret store removes the older file-vault copy of the key, which a failed keystore lookup used to return, or warns that it may remain when `MINTRUN_VAULT_KEY` is not set to decrypt `vault.json`; README documents `MINTRUN_FILE_VAULT=1` for a host whose keystore cannot be reached; Three plugins in `examples/plugins/` that install from a clone (a `bitwarden` vault; `vercel` and `postgres-jit` providers; Python 3.9+ standard library), tested through the CLI against a stub `bw`, a stub `psql`, and a local Vercel API, with `postgres-jit` also run against real PostgreSQL 15 and 16; `-approve` and `require_approval` ask the macOS dialog and a Telegram bot at once and the first answer wins (`approval-telegram` in the default vault; no answer within 10 minutes is not an approval); `94.0%` verified statement coverage, measured in a `git archive v0.9.0` export |

---

## 2. Current Repository Status

- **Plan & Backlog:** [plan.md](plan.md)
- **Verification Report:** [checks.md](checks.md)
- **Security Audit Report:** [audit.md](audit.md)
- **Pipeline Status:**
  - `gofmt -s -l cmd internal` and `go vet ./...`: clean (`0` issues)
  - `go test -count=1 -cover ./...` (without build tags): **94.0%** total statement coverage (`cmd/mintrun` 95.1%, `internal/builtin` 93.7%, `internal/core` 94.2%)
  - `go test -race -count=1 ./...`: pass (`0` data races)
  - `go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list`: pass (`7` built-in plugins registered, `0` local path strings in binary)
  - Cross-compilation (`GOOS=linux`, `GOOS=windows`, `GOOS=freebsd`): pass

---

## 3. Open Items & Next Steps

- **OS Network Sandbox (`no_network: true`):** Optional fail-closed network namespace / `sandbox-exec` isolation for child processes; awaiting approval of the open questions in [plan.md](plan.md).
- **Live 1Password Verification:** Run `mintrun secret set`, `check`, and `rm` against a real 1Password account; the `stdin` item template and the archiving of older items are tested against a mock `op` only.
- **Linux Host Verification:** Verify `secret-tool`, and `-approve` with Telegram as the only channel, on a Linux host.
- **Live Telegram, Bitwarden & Vercel Verification:** Telegram approval, the `bitwarden` vault, and the `vercel` provider are tested against a local Bot API, a stub `bw`, and a local Vercel API only; run each against a real bot or account before calling it verified.
- **Two-Way Slack Approval:** Not built, because an incoming webhook only sends. It needs a Slack app token, `chat.postMessage`, and polling for the answer; Socket Mode needs WebSockets, which the standard library lacks.
- **Audit Read Time:** `TailAudit` bounds memory but still scans the whole log on every read; seek back from the end if it reaches gigabytes.

---

## Checkpoint — Video giới thiệu mintrun (2026-10-15)

- **Hoàn thành:** video 36 s giới thiệu mintrun (1920x1080, 30 fps, nhạc viết riêng bằng Web Audio). Dựng bằng skill motion video của iart-ai (`javascript-animation` + `soundtrack`, v0.4.1, MIT).
- **Outputs:** `docs/video/mintrun-intro.mp4`, `docs/video/mintrun-intro.html` (nguồn; mở bằng trình duyệt, click một lần để có tiếng), `docs/video/storyboard.md`.
- **Nội dung:** 8 cảnh theo vòng đời Policy → Vault → Mint → Exec → Revoke · Scrub · Audit. Chữ trên màn hình tiếng Việt, thuật ngữ giữ tiếng Anh.
- **Quyết định:** không đổi file Go; không thêm skill vào repo; token trên màn hình đều là `FAKE-…`.
- **Kiểm chứng:** mục "Video giới thiệu" trong `checks.md`.
- **Git:** commit cả MP4 (~13 MB) theo xác nhận của bạn ngày 2026-10-16.

## Checkpoint — Plugin mẫu & duyệt lệnh qua Telegram (2026-10-16)

- **Hoàn thành:** Workstream H (3 plugin mẫu cài được ngay sau khi clone) và Workstream I (duyệt lệnh qua Telegram, hỏi song song với hộp thoại macOS).
- **Outputs:** `examples/plugins/{bitwarden,vercel,postgres-jit}/` (`plugin.json` + `run`), `examples/plugins/README.md`, `cmd/mintrun/examples_test.go`, `internal/builtin/telegram.go`, `internal/builtin/telegram_test.go`; sửa `internal/core/runner.go`, `internal/core/core_test.go`, `cmd/mintrun/main.go`.
- **Quyết định:** chưa làm Slack (incoming webhook chỉ gửi một chiều, không nhận lại câu trả lời); cấu hình Telegram chỉ đọc từ vault mặc định, không bao giờ từ vault do agent chọn; quá 10 phút không trả lời là không duyệt; plugin mẫu viết bằng Python thư viện chuẩn, chạy được với Python 3.9 có sẵn trên macOS.
- **Kiểm chứng:** các dòng Approval Channels, Telegram Approval, Example Plugins, `postgres-jit` on Real PostgreSQL và Hermetic Default Test Suite trong `checks.md`; 28/28 mutant đều bị test bắt.
- **Chưa kiểm chứng:** bot Telegram, tài khoản Bitwarden và Vercel thật; máy Linux.
- **Next step:** xong — Workstreams F, G, H, I đã được tag `v0.9.0` tại `8a873f1` (2026-10-16).
