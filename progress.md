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
| **`v0.10.0` — Quoted Approval Text, Slack Approval & Onboarding** | ✅ Done | The macOS approval dialog and the Telegram message show the same text, built by `core.ApprovalText`: every field an agent sets (provider, scope, permissions, params, argv) is quoted, so a line break in an argument shows as `\n` and cannot fake a `Command:` line or push the command out of view, and a control character no longer stops the dialog from opening; the dialog now shows permissions and params and cuts a long request with a TRUNCATED warning; `-approve` and `require_approval` also ask through a Slack bot, which DMs the request and takes the stored user's ✅ or ❌ reaction (`approval-slack` in the default vault; it polls, so no public URL is needed; no answer within 10 minutes is not an approval); `mintrun init` sets up each provider, Telegram approval (a one-time link and a test request) or Slack approval (a test request), a fail-closed GitHub policy, and mintrun in each IDE, checking every value before it is stored, and `mintrun doctor` checks the setup without changing it, printing names only and exiting 1 on a failure; a `policy.json` that exists but cannot be read (a directory, no read permission, a symlink to a missing file) denies every exec as a malformed one does, where it used to allow every exec; a missing secret names the command that stores it (`mintrun init <step>` for a key `init` sets up, `mintrun secret set <key>` for any other); `secret check` shows the vault's error, so a missing secret names that command and a vault it cannot read (a wrong `MINTRUN_VAULT_KEY`) says so instead of calling the secret missing, and a stored secret no longer prints its length; a plugin reply that does not decode fails with a fixed error that quotes none of the reply, where it used to quote part of it (one character of a bare secret, all of a string in `expires_at`); `94.4%` verified statement coverage, measured in a `git archive` export of the commit tagged `v0.10.0` |
| **Unreleased — Approval Dialog Defaults to Deny, Shows Vault and Working Directory & Agents Cannot Pick the Vault or Set the Timeout** | ⏳ Untagged | The macOS approval dialog's default button is Deny, where it used to be Allow, so pressing Return denies a request instead of approving it; the dialog, Telegram, and Slack also show the request's vault and working directory, each quoted like every other field, or `(not set: …)` when the request leaves it empty; an agent's `mintrun_exec` or `mintrun_policy_check` request that names a vault is denied, and the denied `mintrun_exec` is audited with exit 126, because the vault is the operator's choice (`MINTRUN_VAULT`, or the CLI's `-vault`); one that sets `timeout_seconds` is denied the same way, so an agent's command is killed after 5 minutes like the CLI's, and the tools' input schema now lists `approve`, which only adds a human check; `94.1%` verified statement coverage, measured in a `git archive` export |

---

## 2. Current Repository Status

- **Plan & Backlog:** [plan.md](plan.md)
- **Verification Report:** [checks.md](checks.md)
- **Security Audit Report:** [audit.md](audit.md)
- **Pipeline Status:**
  - `gofmt -s -l cmd internal examples` and `go vet ./...`: clean (`0` issues)
  - `go test -count=1 -cover ./...` (without build tags): **94.1%** total statement coverage (`cmd/mintrun` 93.8%, `internal/builtin` 94.0%, `internal/core` 94.7%)
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
- **Approval Text Gaps:** `strconv.Quote` keeps look-alike letters and combining marks as written (the look-alike row in [checks.md](checks.md)); Deny is the dialog's default button, but no test has pressed Return on a real dialog (the Return row in [checks.md](checks.md)).

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
- **Next step:** xong — đã push lên `main` tại `377e44c` (2026-10-17) và được tag `v0.10.0`.

## Checkpoint — Duyệt lệnh qua Slack (2026-10-16)

- **Hoàn thành:** Workstream L. `-approve`, `MINTRUN_APPROVE=1` và `require_approval` hỏi thêm qua một bot Slack, song song với hộp thoại macOS và Telegram: bot nhắn riêng (DM) cho bạn, gắn sẵn ✅ và ❌, rồi đọc reaction mỗi 3 giây. Không cần URL công khai hay WebSocket.
- **Outputs:** `internal/builtin/slack.go`, `internal/builtin/slack_test.go`; sửa `cmd/mintrun/main.go`, `README.md`, `AGENTS.md` (luật 4 và 31, thêm luật 34), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:** cấu hình `approval-slack` (`<user_id>:<bot_token>`) chỉ đọc từ vault mặc định; chỉ reaction của đúng user đó được tính, ❌ thắng ✅; lỗi API (kể cả thiếu scope), quá 10 phút hay bị huỷ đều là lỗi, không bao giờ là duyệt; 429 thì chờ theo `Retry-After`; văn bản dùng chung `core.ApprovalText`, thoát `&`, `<`, `>`, và cắt trước khi thoát để bản đã thoát vừa 3.500 byte.
- **Kiểm chứng:** dòng Slack Approval trong `checks.md`; 31/31 mutant đều bị `TestSlackApproval` bắt.
- **Chưa kiểm chứng:** workspace Slack thật (cần token thật và sự đồng ý của bạn); máy Linux.
- **Next step:** xong — đã push lên `main` tại `ef37972` (2026-10-17) và được tag `v0.10.0`.

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
- **Next step:** xong — đã push lên `main` tại `fda1644` (2026-10-17) và được tag `v0.10.0`.

## Checkpoint — Thiếu secret thì chỉ cách sửa (2026-10-17)

- **Hoàn thành:** Workstream O. Khi vault không có secret, lỗi chỉ đúng lệnh cần chạy: `(run mintrun init github)` cho khoá mà `mintrun init` cài (`github`, `aws`, `gcp`, `cloudflare`; `approval-telegram` là bước `init telegram`, `approval-slack` là bước `init slack`), và `(run mintrun secret set <khoá>)` cho mọi khoá khác. Lỗi vẫn bọc `ErrSecretNotFound`, nên `mintrun doctor` vẫn in `-` (chưa đặt).
- **Outputs:** sửa `internal/builtin/keychain.go`, `internal/builtin/telegram.go`, `internal/builtin/slack.go`, `internal/core/runner.go`, `internal/builtin/{builtin,telegram,slack}_test.go`, `AGENTS.md` (luật 37 mới), `plan.md`, `checks.md`, `progress.md`. README không trích thông báo cũ nên giữ nguyên.
- **Quyết định:**
  - Chỉ vault phân biệt được "không có" với "lỗi", nên gợi ý nằm ở vault, đúng một lần. `ExecBlind` bỏ câu `secret set` nó gắn vào mọi lỗi vault: câu đó sẽ lặp lại gợi ý mới, và còn bảo người nhập sai `MINTRUN_VAULT_KEY` lưu lại secret. Telegram và Slack cũng bỏ gợi ý riêng của chúng.
  - 1Password không thêm gợi ý: `op` báo lỗi giống nhau khi thiếu item, khi chưa đăng nhập hay khi trùng tên, và lỗi đã trích `stderr` của `op` (đã scrub). Lỗi của 1Password và plugin vault vì thế không còn câu `secret set` chung của core; `bitwarden` vẫn tự chỉ `bw sync`.
- **Kiểm chứng:** dòng Missing-Secret Hint trong `checks.md`; 10/10 mutant đều bị test bắt. Trong bản `git archive` của `93f284e`: gofmt và vet sạch, test pass, độ phủ `94.3%` (`cmd/mintrun` 94.7%, `internal/builtin` 94.0%, `internal/core` 94.4%), `-race` pass, build và `plugin list` (7 plugin) pass, build chéo linux, windows, freebsd pass. Riêng commit core (`784db85`) cũng qua vet và test. Quét rò rỉ: 0 hit (đối chứng 17/17 và 10/10).
- **Chưa xử lý:** `secret check` vẫn chỉ in `NOT configured` (đã sửa ở checkpoint sau); khi `MINTRUN_VAULT` chọn vault khác, gợi ý cho vault `keychain` sẽ lưu vào vault mặc định.
- **Next step:** xong — đã push lên `main` tại `22ed79b` (2026-10-17).

## Checkpoint — `secret check` hiện lỗi của vault (2026-10-17)

- **Hoàn thành:** Workstream P. Trước đây `mintrun secret check <khoá>` chỉ in `NOT configured` và bỏ lỗi của vault, nên không hiện lệnh cần chạy, và một `MINTRUN_VAULT_KEY` sai cũng bị báo là thiếu secret. Giờ khi thiếu secret, lệnh vẫn in `NOT configured` kèm lỗi của vault, nên gợi ý `(run mintrun init <bước>)` hay `(run mintrun secret set <khoá>)` hiện đúng một lần; mọi lỗi khác in `could not read vault` kèm lỗi đó. Cả hai thoát với mã 1; giá trị rỗng vẫn là `NOT configured`.
- **Outputs:** sửa `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`, `README.md`, `AGENTS.md` (luật 37 nêu thêm `secret check`), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - Không thêm luật 38: thay đổi chỉ áp dụng luật 37 (chỉ vault phân biệt được thiếu với lỗi, caller chuyển lỗi đi nguyên vẹn) cho thêm một caller, nên luật 37 chỉ thêm một câu.
  - Lỗi của vault không chứa secret, đã soát từng vault: file vault không trích giá trị đã lưu (lỗi keystore chỉ cảnh báo, luật 18); 1Password chỉ trích `stderr` của `op`, không bao giờ `stdout`; plugin vault tự scrub lỗi của nó (luật 32). `ExecBlind` vốn đã trả đúng lỗi này cho agent.
  - Với 1Password, thiếu item cũng hiện là `could not read vault`, vì `op` báo lỗi giống nhau khi thiếu item và khi chưa đăng nhập.
- **Kiểm chứng:** dòng `secret check` Shows the Vault's Error trong `checks.md`; `TestCLISecretCheckReportsVaultError` chạy với `-v` hiện `--- PASS` cho cả 3 ca; 4/4 mutant đều bị test bắt, kể cả mutant bỏ lỗi như cũ. Trong bản `git archive` của `1879479`: gofmt và vet sạch, test pass, độ phủ `94.3%` (`cmd/mintrun` 94.7%, `internal/builtin` 94.0%, `internal/core` 94.4%), `-race` pass, build và `plugin list` (7 plugin) pass, build chéo linux, windows, freebsd pass, binary build với `-trimpath` không chứa đường dẫn home (0; bản đối chứng không `-trimpath`: 3). Quét rò rỉ: 0 hit (đối chứng 24/24 và 10/10).
- **Chưa xử lý:** khi có secret, lệnh vẫn in độ dài của nó (`length=`), thứ luật 35 cấm `doctor` in (đã sửa ở checkpoint sau); lỗi JSON của một plugin trích stdout của nó: một ký tự khi output không phải JSON, cả một chuỗi khi `lease.expires_at` không phải thời gian (có từ trước, `ExecBlind` cũng vậy; đã sửa ở Workstream R).
- **Next step:** xong — đã push lên `main` tại `1c109c6` (2026-10-17).

## Checkpoint — `secret check` không in độ dài secret (2026-10-17)

- **Hoàn thành:** Workstream Q. Khi secret đã có, `mintrun secret check <khoá>` in `(length=<n> chars, value hidden)`, mà độ dài lấy từ chính secret, thứ luật 35 cấm `doctor` in. Bạn chọn bỏ độ dài, nên giờ lệnh chỉ in `Secret "<khoá>" is configured in vault "<vault>" (value hidden).` và thoát với mã 0. Ba nhánh lỗi của Workstream P giữ nguyên.
- **Outputs:** sửa `cmd/mintrun/main.go`, `cmd/mintrun/main_test.go`, `README.md`, `AGENTS.md` (luật 38 mới), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - Thêm luật 38: trước đây không luật nào cấm `secret check` in thứ suy ra từ secret (README còn ghi độ dài), nên đây là bất biến mới chứ không chỉ là áp dụng một luật cũ. Luật áp dụng cho mọi output xác nhận một secret: chỉ nêu khoá và vault, không nêu độ dài, tiền tố hay hash.
  - Đã soát các output khác: `secret set` và `secret delete` chỉ in khoá và vault, còn `doctor` không in độ dài (luật 35). Cảnh báo Keychain khi secret dài quá 24.000 byte có nêu số byte, nhưng đó là giá trị người gọi vừa đưa vào `secret set`, nên không lộ thêm gì.
- **Kiểm chứng:** dòng `secret check` Prints No Length trong `checks.md`; `TestCLISecretCheckConfigured` chạy với `-v` hiện `--- PASS`; 1/1 mutant (in lại độ dài) bị test bắt. Trong bản `git archive` của `914207e`: gofmt và vet sạch, test pass, độ phủ `94.3%` (`cmd/mintrun` 94.7%, `internal/builtin` 94.0%, `internal/core` 94.4%), `-race` pass, build và `plugin list` (7 plugin) pass, build chéo linux, windows, freebsd pass, binary build với `-trimpath` không chứa đường dẫn home (0; bản đối chứng không `-trimpath`: 3). Quét rò rỉ: 0 hit (đối chứng 24/24 và 10/10).
- **Chưa xử lý:** lỗi JSON của một plugin vẫn trích stdout của nó (xem checkpoint trước; là một task riêng; đã sửa ở checkpoint sau).
- **Next step:** xong — đã push lên `main` tại `9ae1b32` (2026-10-17).

## Checkpoint — Lỗi JSON của plugin không trích stdout (2026-10-17)

- **Hoàn thành:** Workstream R. Khi phản hồi của một plugin không giải mã được, `ExternalPlugin.call` trước đây bọc lỗi của `json.Unmarshal`, mà lỗi này trích stdout của plugin: ký tự đầu của một secret in trần (`invalid character 'h' …`), cả chuỗi khi `lease.expires_at` không phải thời gian (`parsing time "…"`). `Scrub` chỉ biết master và secret của một lease đã giải mã được, nên phần bị trích lọt ra `secret check`, `ExecBlind`, MCP và `audit.jsonl`. Giờ lỗi là câu cố định `plugin "<tên>" returned an invalid JSON response`, không trích gì từ stdout. Lỗi stderr và `resp.Error` giữ nguyên, vì plugin tự scrub chúng (luật 32).
- **Outputs:** sửa `internal/core/plugin.go`, `internal/core/core_test.go`, `README.md`, `AGENTS.md` (luật 32 thêm một câu), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - Không thêm luật mới: luật 32 đã cấm plugin trích stdout của helper, nên chỉ thêm một câu nói runner cũng không trích stdout của plugin.
  - Câu lỗi nói "invalid JSON response" chứ không phải "not valid JSON", vì phản hồi có `expires_at` sai vẫn là JSON hợp lệ.
  - README thêm một đoạn ở phần plugin: phản hồi không giải mã được báo câu lỗi cố định và không bị trích, vì nó có thể chứa secret.
  - Nhánh bỏ `length=` lên `main` trước, nên hai commit này được rebase lên `9ae1b32`, workstream đổi tên thành R, và mọi phép đo chạy lại trên cây đã gộp.
- **Kiểm chứng:** dòng Plugin JSON Errors Quote Nothing trong `checks.md`; `TestPluginInvalidJSONNeverQuotesStdout` chạy với `-v` hiện `--- PASS` cho cả 2 ca (`bare_secret`, `expires_at`). Code cũ trượt cả 2 ca; trên bản sao của cây đã rebase, mutant bọc lại lỗi trượt cả 2 ca, còn bản sao không đổi thì pass. Trong bản `git archive` của `3abd864`: gofmt và vet sạch, test pass, độ phủ `94.4%` (`cmd/mintrun` 94.7%, `internal/builtin` 94.0%, `internal/core` 94.6%), `-race` pass, build và `plugin list` (7 plugin) pass, binary `-trimpath` chứa 0 đường dẫn home (đối chứng không `-trimpath`: 760), build chéo linux, windows, freebsd pass. Quét rò rỉ: 0 hit (đối chứng 24/24 và 10/10).
- **Chưa xử lý:** không có.
- **Next step:** xong — đã push lên `main` tại `b36f908` (2026-10-17); Workstreams K, L, M, N, O, P, Q, R đã được tag `v0.10.0` (2026-10-17).

## Checkpoint — Hộp thoại duyệt mặc định Deny, hiện vault và thư mục làm việc (2026-10-17)

- **Hoàn thành:** Workstream S, đóng hai mục của Approval Text Gaps. Hộp thoại macOS trước đây có `default button "Allow"`, nên lỡ bấm Return là duyệt lệnh; giờ Deny vừa là nút mặc định vừa là nút huỷ, nên Return cũng như Esc trả `-128`, vẫn là trường hợp duy nhất ra `(false, nil)` (luật 31). `core.ApprovalText` trước đây không hiện `ExecRequest.Vault` và `ExecRequest.WorkingDir`, hai trường agent đặt được qua MCP `mintrun_exec` (`vault`, `cwd`); giờ dòng `Vault:` đứng sau provider và dòng `Working directory:` đứng cuối, cả hai qua `strconv.Quote` (luật 4), nên một xuống dòng hay U+202E trong thư mục làm việc hiện thành escape. Giá trị rỗng hiện `(not set: the default vault)` hoặc `(not set: mintrun's own)`, không có ngoặc kép, nên không giá trị nào của agent giả được. Hộp thoại, Telegram và Slack hiện cùng một văn bản, và giới hạn giữ nguyên (1.000 byte trong hộp thoại, 3.500 trong Telegram, Slack theo luật 34).
- **Outputs:** sửa `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/telegram_test.go`, `internal/builtin/slack_test.go`, `README.md`, `AGENTS.md` (luật 4, 31 và 34), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - Không thêm luật mới: luật 4 thêm vault, thư mục làm việc và chữ `(not set: …)`; luật 31 thêm Deny là nút mặc định; luật 31 và 34 thêm hai trường này vào danh sách đi qua máy chủ của Telegram và Slack.
  - Giá trị rỗng không được phân giải: văn bản không tra vault mặc định hay thư mục của `mintrun`, nên một yêu cầu không đặt thư mục làm việc không gửi đường dẫn cục bộ nào tới Telegram hay Slack. Thư mục agent đặt thì vẫn đi qua máy chủ của họ và thường chứa tên người dùng; README nói rõ điều này.
  - Thư mục làm việc đứng sau lệnh, nên một lệnh dài đẩy nó ra sau cảnh báo TRUNCATED, mà cảnh báo đó vốn bảo từ chối.
  - Dòng `Vault:` mới dời điểm cắt của yêu cầu dài trong test lên đúng ranh giới một rune, và `TestOSApproval` không còn bắt được mutant bỏ bước cắt theo UTF-8. Điểm cắt có rơi giữa một rune hay không tuỳ vào mọi byte đứng trước, nên phép thử dài giờ chạy hai lần, có và không có 1 byte đệm; luật 4 ghi lại bài học này.
  - Bản `v0.10.0` lên `main` trong lúc làm, nên hai commit được rebase lên `9865bf9`; cây Go giống hệt bản trước khi rebase.
- **Kiểm chứng:** dòng Approval Channels, Approval Text và dòng Return trong `checks.md`; `TestOSApproval`, `TestTelegramApproval` và `TestSlackApproval` chạy với `-v` đều hiện `--- PASS`. Trên bản sao của `d71e85b`, 13/13 mutant đều làm `TestOSApproval` trượt (Allow là nút mặc định; bỏ dòng vault; bỏ dòng thư mục làm việc; vault, thư mục làm việc, argv, provider hay params không quote; bỏ chữ not set; hộp thoại cũ không quote, kể cả khi test bỏ U+202E; không giới hạn; không cắt theo UTF-8; `%+q` trong hộp thoại), 8 mutant trong số đó cũng làm `TestTelegramApproval` và `TestSlackApproval` trượt, còn bản sao không đổi thì pass; trước khi có byte đệm, mutant không cắt theo UTF-8 qua được `TestOSApproval`. `osacompile` của script mới thoát 0. Trong bản `git archive` của `d71e85b`: gofmt và vet sạch, test pass, độ phủ `94.4%` (`cmd/mintrun` 94.7%, `internal/builtin` 94.0%, `internal/core` 94.6%), `-race` pass, build và `plugin list` (7 plugin) pass, binary `-trimpath` chứa 0 đường dẫn home (đối chứng không `-trimpath`: 760), build chéo linux, windows, freebsd pass. Quét rò rỉ: 0 hit (đối chứng 25/25 và 10/10).
- **Chưa xử lý:** chưa ai bấm Return trên một hộp thoại thật (dòng Return trong `checks.md` §3 có lệnh để tự thử); `strconv.Quote` vẫn giữ nguyên chữ trông giống nhau và dấu kết hợp (dòng look-alike); input schema của `mintrun_exec` và bảng MCP trong README nêu `cwd` mà không nêu `vault`, dù agent vẫn gửi được (mục MCP `vault` Field ở phần 3).
- **Next step:** xong — đã push lên `main` tại `70093ff` (2026-10-17).

---

## 23. Workstream T — CLI Shims (`mintrun shim`: Block & Redirect + Transparent Auto-Wrap)

- **Hoàn thành:** Bước T1 → T4 trong `plan.md`.
- **Files thay đổi:** `cmd/mintrun/shim.go`, `cmd/mintrun/shim_test.go`, `cmd/mintrun/main.go`, `cmd/mintrun/setup.go`, `README.md`, `AGENTS.md`, `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - **Nhận diện qua `os.Args[0]` (`invokedShimName`):** khi `mintrun` được gọi qua symlink mang tên `gh`, `aws`, `gcloud`, `wrangler`, `vercel`, hoặc `psql` (kể cả hậu tố `.exe`), `main()` chuyển thẳng vào `runShim` trước khi phân tích subcommand của `mintrun`.
  - **2 chế độ hoạt động (`block` mặc định & `auto`):**
    - `block`: từ chối chạy trực tiếp với mã thoát `126` (không mở vault, không chạy binary thật) và in thông báo hướng dẫn gọi MCP tool `"mintrun_exec"` kèm câu lệnh `mintrun exec -provider <provider> -scope <scope> -perms <perms> -- <tool> ...` để AI agent tự sửa ở lượt kế tiếp.
    - `auto`: tự động loại `<home>/shims` khỏi `PATH` (`withoutShimsOnPath`), tìm binary thật tuyệt đối ngoài `<home>/shims` (`lookPathSkippingDir`, từ chối mọi mục `PATH` tương đối theo Luật 14), suy luận scope cho `gh` từ `-R`/`--repo` hoặc `git remote get-url origin` (không in URL), hoặc lấy từ 1 rule cụ thể trong `policy.json`, rồi gọi `rt.ExecBlind`.
  - **Biến môi trường chỉ thắt chặt (Luật 11 & 39):** `MINTRUN_SHIM_MODE=block` siết `auto` thành `block`, còn `MINTRUN_SHIM_MODE=auto` không bao giờ nới lỏng `block` thành `auto`.
  - **Chống đệ quy vô tận:** `cmdExec`, `cmdMCP` và `runShim` đều gọi `withoutShimsOnPath(rt.HomeDir)` để `ExecBlind` luôn chạy binary thật.
  - **`doctorShims`:** kiểm tra `<home>/shims/config.json`, đích symlink và thứ tự `PATH` khi thư mục `<home>/shims` tồn tại.
- **Kiểm chứng:** `go test -count=1 -v -run 'TestCLIShim|TestCLIDoctor' ./cmd/mintrun` pass toàn bộ subtest; 12/12 mutant trên bản sao đều bị bắt; `gofmt` & `go vet` 0 lỗi; độ phủ toàn repo đạt **94.3%** (`cmd/mintrun` 94.4%, `internal/builtin` 94.0%, `internal/core` 94.6%).
- **Next step:** xong — đã push lên `main` tại `2619790` (2026-10-17).

## Checkpoint — Agent không được chọn vault (2026-10-17)

- **Hoàn thành:** Workstream U, đóng mục "MCP `vault` Field" ở phần 3. `mintrun_exec` và `mintrun_policy_check` giải mã tham số thẳng vào `core.ExecRequest`, nên agent gửi được `vault` và chọn vault để đọc master secret, dù input schema và bảng MCP trong README không hề nêu trường này. Giờ vault là lựa chọn của người vận hành (`MINTRUN_VAULT`, hoặc `-vault` của CLI): bridge đặt `ExecRequest.FromAgent` sau khi giải mã tham số của cả hai tool, và `CheckPolicy` từ chối yêu cầu của agent có nêu bất kỳ vault nào, kể cả vault mặc định. Vì lệnh từ chối nằm trong `CheckPolicy` (luật 16), `mintrun_exec` ghi audit với exit 126 trước khi mở vault nào, và `mintrun_policy_check` trả đúng lý do đó. CLI không đặt cờ, nên `-vault` chạy như cũ.
- **Outputs:** sửa `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/mcp.go`, `internal/builtin/builtin_test.go`, `README.md`, `AGENTS.md` (luật 16 và 31), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - Theo lựa chọn của bạn: từ chối `vault` từ MCP, thay vì liệt kê nó trong schema hay thêm một cổng policy mới.
  - Hai lớp chặn độc lập: cờ có tag `json:"-"`, nên không tham số nào đặt hay xoá được nó, và bridge đặt cờ sau khi giải mã.
  - Yêu cầu nêu đúng vault mặc định cũng bị từ chối: quy tắc đơn giản hơn, và agent không có lý do để gửi trường này.
  - Lý do từ chối trích tên vault agent gửi (dữ liệu của chính agent, không phải secret) và nhắc `MINTRUN_VAULT`.
  - CLI shims (`2619790`) lên `main` trước, nên hai commit được rebase lên đó; workstream này đổi thành U vì shims đã dùng chữ T.
  - Schema vẫn không nêu `vault`; README thêm một đoạn ngay sau bảng MCP và sửa dòng "Every field quoted" thành "each field of the request".
- **Kiểm chứng:** dòng Agents Cannot Pick the Vault trong `checks.md`; `TestCheckPolicyMatchesExecBlind` và `TestMCPBridgeRefusesVault` chạy với `-v` đều hiện `--- PASS`. Trên bản sao repo, 11/11 mutant đều làm ít nhất một test trượt, không cái nào do lỗi build (một lỗi biên dịch cài sẵn được nhận ra là lỗi build), còn bản sao không đổi thì pass. Trong bản `git archive` của `92b01b4`: gofmt và vet sạch, test pass, độ phủ `94.4%` (`cmd/mintrun` 94.7%, `internal/builtin` 94.0%, `internal/core` 94.6%), `-race` pass, build và `plugin list` (7 plugin) pass, binary `-trimpath` chứa 0 đường dẫn home (đối chứng không `-trimpath`: 760), build chéo linux, windows, freebsd pass. Quét rò rỉ: 0 hit (đối chứng 24/24 và 10/10).
- **Chưa xử lý:** `mintrun_exec` vẫn giải mã `timeout_seconds` và `approve` dù schema và README không nêu; `approve` chỉ thêm bước hỏi người, nhưng `timeout_seconds` cho agent nâng mức mặc định 5 phút (mục MCP Fields Outside the Schema ở phần 3; đã sửa ở checkpoint sau).
- **Next step:** xong — đã push lên `main` tại `27c078b` (2026-10-17).

## Checkpoint — Agent không được đặt timeout (2026-10-17)

- **Hoàn thành:** Workstream V, đóng mục "MCP Fields Outside the Schema" ở phần 3. Lệnh của agent giờ luôn bị dừng sau 5 phút, như lệnh chạy bằng `mintrun exec`. `CheckPolicy` từ chối yêu cầu của agent đặt `timeout_seconds` khác 0, ngay sau kiểm tra vault và trước khi tra rule của provider, nên `mintrun_exec` ghi audit với exit 126 và `mintrun_policy_check` trả đúng lý do đó, kể cả với provider không có rule trong `policy.json`. Input schema của hai tool giờ nêu `approve`, và `TestMCPExecSchema` buộc schema nêu mọi trường `ExecRequest` giải mã được, trừ `vault` và `timeout_seconds` (bị từ chối).
- **Outputs:** sửa `internal/core/runner.go`, `internal/core/core_test.go`, `internal/builtin/mcp.go`, `internal/builtin/builtin_test.go`, `README.md`, `AGENTS.md` (luật 16), `plan.md`, `checks.md`, `progress.md`.
- **Quyết định:**
  - Theo lựa chọn của bạn: từ chối `timeout_seconds` từ MCP, thay vì nêu nó trong schema hay thêm mức trần trong policy.
  - Giá trị âm cũng bị từ chối (`!= 0`, không phải `> 0`): agent không có lý do gửi trường này.
  - `approve` được nêu trong schema vì nó chỉ thêm bước hỏi người; nó không tắt được `MINTRUN_APPROVE` hay `require_approval` của policy.
  - CLI không có cờ timeout, nên chú thích và lý do từ chối không ngụ ý người vận hành đặt được nó; README ghi "5 minutes" thay cho "5 min by default".
  - Thêm ca provider không có rule, vì 2 mutant (dời kiểm tra timeout, hoặc kiểm tra vault, vào trong `if hasRule`) sống sót khi chưa có ca này.
  - `main` di chuyển hai lần trong lúc làm (`27c078b`, rồi `c5cea73` của CLI shims), nên commit code được rebase lên `c5cea73`; cây `internal/` không đổi.
- **Kiểm chứng:** dòng Agents Cannot Set the Timeout trong `checks.md`; `TestCheckPolicyMatchesExecBlind`, `TestMCPBridgeGovernanceTools`, `TestMCPBridgeRefusesVault`, `TestMCPBridgeRefusesTimeout` và `TestMCPExecSchema` chạy với `-v` đều hiện `--- PASS`. Trên bản sao của `7da79b5` (cây `internal/` giống hệt `58f2dc9`), 17/17 mutant đều làm ít nhất một test trượt, không cái nào do lỗi build; bản sao không đổi và bản chỉ sửa chú thích thì pass, còn một lỗi biên dịch cài sẵn được nhận ra là lỗi build. Trong bản `git archive` của `58f2dc9`: gofmt và vet sạch, test pass, độ phủ `94.1%` (`cmd/mintrun` 93.8%, `internal/builtin` 94.0%, `internal/core` 94.7%; `c5cea73` cũng đo `94.1%`, còn `27c078b` đo `94.3%` với `cmd/mintrun` 94.4%), `-race` pass, build và `plugin list` (7 plugin) pass, binary `-trimpath` chứa 0 đường dẫn home (đối chứng không `-trimpath`: 760), build chéo linux, windows, freebsd pass. Quét rò rỉ: 0 hit (đối chứng 24/24 và 10/10).
- **Chưa xử lý:** không có.
- **Next step:** push lên `main` khi bạn đồng ý.
