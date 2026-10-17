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
| **Unreleased — Quoted Approval Text, Slack Approval & Onboarding** | ⏳ Untagged | The macOS approval dialog and the Telegram message show the same text, built by `core.ApprovalText`: every field an agent sets (provider, scope, permissions, params, argv) is quoted, so a line break in an argument shows as `\n` and cannot fake a `Command:` line or push the command out of view, and a control character no longer stops the dialog from opening; the dialog now shows permissions and params and cuts a long request with a TRUNCATED warning; `-approve` and `require_approval` also ask through a Slack bot, which DMs the request and takes the stored user's ✅ or ❌ reaction (`approval-slack` in the default vault; it polls, so no public URL is needed; no answer within 10 minutes is not an approval); `mintrun init` sets up each provider, Telegram approval (a one-time link and a test request) or Slack approval (a test request), a fail-closed GitHub policy, and mintrun in each IDE, checking every value before it is stored, and `mintrun doctor` checks the setup without changing it, printing names only and exiting 1 on a failure; a `policy.json` that exists but cannot be read (a directory, no read permission, a symlink to a missing file) denies every exec as a malformed one does, where it used to allow every exec; `94.3%` verified statement coverage |

---

## 2. Current Repository Status

- **Plan & Backlog:** [plan.md](plan.md)
- **Verification Report:** [checks.md](checks.md)
- **Security Audit Report:** [audit.md](audit.md)
- **Pipeline Status:**
  - `gofmt -s -l cmd internal examples` and `go vet ./...`: clean (`0` issues)
  - `go test -count=1 -cover ./...` (without build tags): **94.3%** total statement coverage (`cmd/mintrun` 94.7%, `internal/builtin` 94.0%, `internal/core` 94.4%)
  - `go test -race -count=1 ./...`: pass (`0` data races)
  - `go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list`: pass (`7` built-in plugins registered, `0` local path strings in binary)
  - Cross-compilation (`GOOS=linux`, `GOOS=windows`, `GOOS=freebsd`): pass

---

## 3. Open Items & Next Steps

- **Child Sandbox (`sandbox: true`):** keep the blind command out of `~/.mintrun` and the Keychain with a macOS `sandbox-exec` profile; designed with spike evidence in [plan.md](plan.md) §3 item 1, awaiting approval. `no_network` stays open.
- **Team Relay (`mintrun relay`):** a server that holds the masters and hands laptops leases only; designed in [plan.md](plan.md) §3 item 6, awaiting approval.
- **Live 1Password Verification:** Run `mintrun secret set`, `check`, and `rm` against a real 1Password account; the `stdin` item template and the archiving of older items are tested against a mock `op` only.
- **Linux Host Verification:** Verify `secret-tool`, and `-approve` with Telegram and Slack as the only channels, on a Linux host.
- **Live Telegram, Slack, Bitwarden & Vercel Verification:** Telegram and Slack approval (with `mintrun init telegram` and `init slack`, which link the bot and send a test request), the `bitwarden` vault, and the `vercel` provider are tested against a local Bot API, a local Slack Web API, a stub `bw`, and a local Vercel API only; run each against a real bot, workspace, or account before calling it verified. The steps are in [plan.md](plan.md) §3 items 3 and 4.
- **Real IDE Verification:** run `mintrun init mcp`, then `mintrun doctor`, against a real Claude Code, Cursor, Claude Desktop, and Antigravity; the entries are checked against stubs, a fake `HOME`, and the vendors' docs only. `CLAUDE_CONFIG_DIR` is not read yet.
- **Audit Read Time:** `TailAudit` bounds memory but still scans the whole log on every read; seek back from the end if it reaches gigabytes.
- **Approval Text Gaps:** The macOS dialog's default button is "Allow", so Return approves; `strconv.Quote` keeps look-alike letters and combining marks as written (the look-alike row in [checks.md](checks.md)); no approver shows `Vault` or `WorkingDir`, both of which an agent sets.

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

## Checkpoint — Cài plugin mẫu theo tên, thiết kế sandbox & relay (2026-10-16)

- **Hoàn thành:** `mintrun plugin install <tên>` cài `bitwarden`, `vercel`, `postgres-jit` từ bản đóng gói sẵn trong binary, không cần clone hay tải về; thiết kế sandbox cho tiến trình con, relay cho team và các bước kiểm thử trên tài khoản thật (đều trong `plan.md` §3).
- **Outputs:** `examples/plugins/embed.go` (mới), `cmd/mintrun/main.go`, `cmd/mintrun/examples_test.go`, `README.md`, `examples/plugins/README.md`, `plan.md`, `checks.md`, `AGENTS.md` (rule 17, 22, 23; rule 33 mới).
- **Quyết định:** tên trần luôn cài bản trong binary, không bao giờ cài thư mục cùng tên ở thư mục hiện tại (repo lạ có thể cài sẵn thư mục đó); muốn cài thư mục thì ghi đường dẫn (`./bitwarden`). Chưa làm danh mục plugin từ xa cho bên thứ ba. Sandbox và relay mới là thiết kế, chờ duyệt (AGENTS.md layer 1).
- **Kiểm chứng:** dòng Install by Name, Child sandbox, Team relay và Parent environment on macOS trong `checks.md`; 5/5 mutant bị `TestPluginInstallCatalog` bắt.
- **Phát hiện:** trên macOS 27.0, tiến trình con không đọc được biến môi trường của tiến trình cha qua `ps -E` hay `sysctl`, nên README §5 và rule 23 đã được sửa lại cho đúng phiên bản này.
- **Chưa kiểm chứng:** sandbox chặn một item Keychain thật (cần bạn đồng ý tạo item thử); Linux; Telegram, 1Password, Bitwarden, Vercel trên tài khoản thật.
- **Next step:** chờ bạn chọn hướng onboarding (đề xuất: `mintrun init` + `mintrun doctor` trước) và duyệt thiết kế sandbox.

## Checkpoint — Yêu cầu duyệt trích dẫn mọi trường (2026-10-16)

- **Hoàn thành:** Workstream K. Hộp thoại macOS và tin nhắn Telegram dựng văn bản bằng cùng một hàm `core.ApprovalText`: mọi trường do agent đặt đều nằm trong dấu ngoặc kép, nên dấu xuống dòng trong một đối số hiện thành `\n` và không giả được dòng `Command:`. Hộp thoại hiện thêm permissions và params, cắt ở 1.000 byte kèm cảnh báo TRUNCATED; tin nhắn Telegram giữ nguyên từng byte.
- **Outputs:** sửa `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/telegram.go`.
- **Kiểm chứng:** dòng Approval Text trong `checks.md`; 7/7 mutant đều bị `TestOSApproval` bắt; `osascript` thật đọc literal của hộp thoại ra đúng văn bản từng byte.
- **Chưa xử lý:** mục Approval Text Gaps ở phần 3.
- **Next step:** tag bản mới khi bạn đồng ý.

## Checkpoint — Duyệt lệnh qua Slack (2026-10-16)

- **Hoàn thành:** Workstream L. `-approve`, `MINTRUN_APPROVE=1` và `require_approval` hỏi thêm qua một bot Slack, song song với hộp thoại macOS và Telegram: bot nhắn riêng (DM) cho bạn, gắn sẵn ✅ và ❌, rồi đọc reaction mỗi 3 giây. Không cần URL công khai hay WebSocket.
- **Outputs:** `internal/builtin/slack.go`, `internal/builtin/slack_test.go`; sửa `cmd/mintrun/main.go`, `README.md`, `AGENTS.md` (luật 4 và 31, thêm luật 34), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:** cấu hình `approval-slack` (`<user_id>:<bot_token>`) chỉ đọc từ vault mặc định; chỉ reaction của đúng user đó được tính, ❌ thắng ✅; lỗi API (kể cả thiếu scope), quá 10 phút hay bị huỷ đều là lỗi, không bao giờ là duyệt; 429 thì chờ theo `Retry-After`; văn bản dùng chung `core.ApprovalText`, thoát `&`, `<`, `>`, và cắt trước khi thoát để bản đã thoát vừa 3.500 byte.
- **Kiểm chứng:** dòng Slack Approval trong `checks.md`; 31/31 mutant đều bị `TestSlackApproval` bắt.
- **Chưa kiểm chứng:** workspace Slack thật (cần token thật và sự đồng ý của bạn); máy Linux.
- **Next step:** tag bản mới khi bạn đồng ý.

## Checkpoint — Onboarding: `mintrun init` & `mintrun doctor` (2026-10-17)

- **Hoàn thành:** Workstream M. `mintrun init` hỏi lần lượt từng phần: GitHub, AWS, GCP, Cloudflare, duyệt lệnh qua Telegram hoặc Slack, policy cho GitHub, và thêm mintrun vào IDE; `mintrun init <phần>` làm riêng một phần. Mọi giá trị được kiểm tra trước khi lưu, token và secret gõ ẩn. `mintrun doctor` kiểm tra cài đặt mà không đổi gì, chỉ in tên (không bao giờ in giá trị), và thoát 1 khi có FAIL.
- **Outputs:** `cmd/mintrun/setup.go`, `cmd/mintrun/setup_test.go` (mới); sửa `cmd/mintrun/main.go`, `internal/builtin/{telegram,slack,cloudflare,keychain}.go`, `internal/builtin/{telegram,slack}_test.go`, `README.md`, `AGENTS.md` (luật 35 mới), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - Telegram: link dùng một lần; chỉ tin nhắn `/start <mã>` đúng mã mới được nhận, nên người khác nhắn bot không thể tự liên kết. Bạn xác nhận tên người gửi trước khi lưu, rồi `init` gửi một yêu cầu duyệt thử qua đúng đường `-approve` dùng.
  - Slack không có link chứng minh member ID là của bạn, nên `init` hỏi bạn có tự trả lời yêu cầu thử không, và xoá cài đặt nếu không phải bạn.
  - Policy gợi ý ở thế đóng: một `owner/repo` lấy từ remote `origin` (không in URL vì có thể chứa token), `clean_env: true`, không bao giờ `allow_static`; không đổi `policy.json` đã có.
  - IDE: Claude Code qua `claude mcp add -s user`; Cursor qua link cài đặt (Cursor tự hỏi lại); Claude Desktop và Antigravity chỉ sửa file sau khi bạn đồng ý, có bản sao lưu. Không cấu hình nào chứa `MINTRUN_VAULT_KEY`.
- **Kiểm chứng:** các dòng Telegram Link, Onboarding: `mintrun init`, `mintrun doctor` và Hermetic Default Test Suite trong `checks.md`; 63/63 mutant đều bị test bắt; độ phủ `94.3%`.
- **Chưa kiểm chứng:** IDE thật (Claude Code, Cursor, Claude Desktop, Antigravity), bot Telegram và workspace Slack thật; `CLAUDE_CONFIG_DIR` chưa được đọc.
- **Next step:** xong — đã push lên `main` tại `c9d74a6` (2026-10-17).

## Checkpoint — `policy.json` không đọc được thì từ chối mọi lệnh (2026-10-17)

- **Hoàn thành:** Workstream N. Trước đây, một `policy.json` có tồn tại nhưng không đọc được (là thư mục, không có quyền đọc, lỗi I/O) bị coi như không có policy, nên mọi lệnh `exec` đều được chạy. Giờ chỉ khi file không tồn tại mới là "không có policy"; mọi lỗi đọc khác từ chối mọi lệnh, giống như khi file sai cú pháp JSON, và `CheckPolicy` (cả MCP `mintrun_policy_check`) lẫn `ExecBlind` từ chối với cùng một lý do.
- **Outputs:** sửa `internal/core/runner.go`, `internal/core/core_test.go`, `cmd/mintrun/setup.go`, `cmd/mintrun/setup_test.go`, `README.md`, `AGENTS.md` (luật 36 mới), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - "Không tồn tại" được xét bằng `os.Lstat`, không dựa vào lỗi của `ReadFile`: với một symlink trỏ tới file không tồn tại, `ReadFile` cũng trả về `ErrNotExist`, nên xét theo lỗi đó thì symlink hỏng vẫn cho mọi lệnh chạy. Phần này làm thêm so với yêu cầu ban đầu.
  - Lý do từ chối và cảnh báo trên `stderr` chỉ giữ nguyên nhân (`is a directory`, `permission denied`…), không giữ đường dẫn, vì lý do đó tới tay agent và nằm trong `audit.jsonl`.
  - `mintrun doctor` xét "không có policy" cùng cách đó và báo FAIL "exec denies every request" (trước đây là "exec then allows every request").
- **Kiểm chứng:** dòng Unreadable `policy.json` trong `checks.md`; 7/7 mutant đều bị test bắt, kể cả mutant trả lại lệnh `return` cũ; độ phủ `94.3%`, đo trong bản `git archive`.
- **Chưa kiểm chứng:** chạy test dưới quyền root (khi là root, ca `chmod 000` được bỏ qua vì root vẫn đọc được file; ca thư mục và symlink hỏng vẫn chạy).
- **Next step:** push 3 commit lên `main` khi bạn đồng ý; tag bản mới khi bạn muốn.
