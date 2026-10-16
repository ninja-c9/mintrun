# mintrun: video giới thiệu (36 s): storyboard

Phim được vẽ hoàn toàn bằng code trên canvas (skill `javascript-animation` + `soundtrack` của iart-ai). Nguồn: `mintrun-intro.html`. Mọi số liệu dưới đây là dữ liệu thật trong trang (`BPM`, `SHOTS`, `EVENTS`, `K`).

## Brief

- **Người xem:** dev và team platform đang cho AI agent (Claude Code, Cursor, MCP client…) chạy lệnh deploy.
- **Một ý duy nhất:** agent được *quyền* deploy, nhưng không bao giờ *cầm* khóa gốc (*Separate Authority from Possession*).
- **Dạng phim:** explainer, mỗi cảnh một bước (3–6 s/cảnh). Mở bằng câu hỏi, có bộ đếm 5 bước luôn hiện trên đầu, kết bằng một dòng tóm tắt.
- **Ngôn ngữ:** chữ tiếng Việt, giữ thuật ngữ tiếng Anh (Policy, Vault, JIT, scope, TTL…).

## Look

- **Phong cách:** blueprint tối của một "enclave". Khối phẳng, đường dựng hình nét đứt, ánh glow. Không viền tay, `LOOK.wobble = 0`.
- **Bảng màu:**
  - nền `#090B10`
  - mint `#34D399` (màu chủ đạo, là "an toàn"), sky `#38BDF8` (agent, request)
  - violet `#A78BFA` (vault), amber `#FBBF24` (bí mật bị lộ), rose `#F43F5E` (bị chặn)
- **Chữ:** SF Pro (system-ui) cho tiếng Việt; SF Mono/Menlo chỉ cho code ASCII.
- **Nhân vật:** robot "AI agent", một hàm `robot()` với các biểu cảm neutral, surprised, worried, relieved, happy.

## Beat grid

120 BPM: 1 beat = 0,5 s, 1 ô nhịp = 2 s. Tổng 72 beat = 18 ô nhịp = 36 s.

- Các cut nằm ở beat 12, 20, 28, 36, 44, 52, 60, tức 6, 10, 14, 18, 22, 26, 30 s. Mỗi cut rơi vào phách mạnh và một hợp âm chủ.
- Dạng nhạc *steps*: mỗi bước một motif. Break im lặng ở beat 58–60 trước cảnh tóm tắt.

## Shot list

| # | from–to (beats) | framing | camera move | what happens (the action) | blocking | action lands on | sound | transition |
|---|---|---|---|---|---|---|---|---|
| 1 | 0–12 | medium (robot + context) | slow push 1.40→1.46 | Câu hỏi "Đưa khóa gốc cho AI agent?". Agent chạy `$ printenv`, token `FAKE-Kx7f…9Qz` in ra stdout, 3 bản sao bay vào stdout / transcript / log, rồi hiện 3 thẻ rủi ro | robot trái, panel context giữa, 3 thẻ log phải | b1 câu hỏi, b2 lệnh, b3 rò rỉ, b4–6 bản sao, b7–9 thẻ | type, type, leak, leak×3, blip×3 | pull out liên tục |
| 2 | 12–20 | medium → wide | pull out 1.46→0.47 | Dòng token bị gạch, chìa khóa gốc bay vào vault. Enclave được dựng (nét đứt → khối). Tiêu đề "mintrun" và "Tách quyền hạn khỏi việc giữ khóa". Robot thở phào và gửi request `printenv` | toàn cảnh: robot trái, enclave phải | b13 khóa bay, b15 cửa vault, b16 tiêu đề, b17 phụ đề, b18 robot, b19 request | whoosh, build, clunk, title, blip, tick, whoosh | cut đẩy vào cổng (card băng qua cut) |
| 3 | 20–28 | medium on gate | drift | Request `$ printenv` đâm vào chắn đỏ, hiện "✗ chặn dump env" rồi tan. Request `$ wrangler deploy` đến; check lệnh/scope/TTL ✓; chắn mở | cổng ở tường trái enclave, card trượt trên sàn từ trái | b21 chặn, b22 tan, b23–24 check, b25 mở cổng | deny, shatter, tick×3, gate, whoosh | card đi ra mép phải, sang cảnh 4 |
| 4 | 28–36 | close on vault | push 1.7→1.77 | Card dừng trước vault; dial quay, cửa mở, khóa gốc phát sáng nhưng **không rời vault**. Một chùm tia mang quyền sang máy mint | vault giữa, máy mint mép phải | b29 dial, b30 mở, b32 tia, b34 đóng cửa | dial, unlock, beam, clunk | card đi phải, sang cảnh 5 |
| 5 | 36–44 | medium on press | drift | Card lên bàn ép; ép xuống thành **token JIT**; màn hình hiện `example.com` / `dns:write · 300s`; vòng TTL bắt đầu cạn | máy mint giữa, vault trái, capsule phải | b38 stamp, b38.5 màn hình, b39 TTL, b40 nhấc, b41 token đi | stamp, type, tick, blip, whoosh | token đi phải, sang cảnh 6 |
| 6 | 44–52 | wide (capsule + cloud) | drift | Token cắm vào ngăn env của **subprocess**, phủ mờ (agent không thấy). `$ npx wrangler deploy` chạy, lỡ in token ra stdout, tia ra cloud: "✓ deployed" | capsule trái, audit giữa, cloud ngoài tường phải | b45 cắm, b45.5 che, b46 lệnh, b47.5 lộ, b48 tia, b49 deployed | inject, blip, type, leak, beam, deploy | cut đẩy vào terminal |
| 7 | 52–60 | close on terminal + audit | slow pull 1.45→1.38 | `exit 0`; token bị **revoke** (đốt); thanh quét thay token bằng `[MINTRUN:REDACTED]`; ghi dòng `audit.jsonl`; gói kết quả bay về agent. Break im lặng | terminal trái, audit phải | b53 exit, b54 revoke, b55 scrub, b56 audit, b56.5 gói, b57 xong | tick, burn, swish, tick, packet, tick | im lặng, cut sang cảnh 8 |
| 8 | 60–72 | extra wide recap | slow push 0.405→0.42 | Gói kết quả rơi vào context của agent và robot vui. Chuỗi 5 bước nối mũi tên, wordmark, tagline, lệnh CLI, 4 chip đặc tính. Giữ khung cuối | cả thế giới trong một dải phía trên, chữ bên dưới | b61 gói, b61.5 chuỗi, b62–63 tagline, b64 CLI, b66–67.5 chip | blip, build, title×2, type, blip×4 | giữ, nhạc fade |

## Blocking (một thế giới, nhiều camera)

Tọa độ world, y hướng xuống, sàn ở y = 300.

| Vật | Vị trí (world) |
|---|---|
| Robot (đầu) | (−2180, −60) |
| Panel context | x −1960…−1480 |
| Thẻ stdout / transcript / log | x −1460…−1270 |
| Enclave | x −900…1360, y −440…300 |
| Cổng policy | tường trái, y 120…300 |
| Vault | x −700…−440 |
| Máy mint | tâm x −120 |
| Capsule subprocess | x 160…800 |
| audit.jsonl | x 870…1290 |
| Cloud | (1760, −230) |

- Mọi request và token trượt trên sàn từ trái sang phải. Hướng màn hình không đổi qua các cut.
- Gói kết quả bay vòng ngược về agent ở cảnh 7–8.

## Soundtrack (Web Audio, viết riêng cho phim này)

Fa trưởng / Rê thứ. Mỗi cảnh đi về hợp âm át (C) và cut rơi vào hợp âm chủ (F).

- **Cut sang vault (beat 28):** dùng kết lừa C → Dm9.
- **Lớp nhạc:** mỗi ô nhịp chỉ thêm 1 lớp:

  | Ô nhịp | Thêm lớp |
  |---|---|
  | 0 | pad + hat |
  | 1 | bass |
  | 2 | kick nửa nhịp |
  | 4 | arp có delay |
  | 6 | kick 4/4 |
  | 8 | clap |

- **Ô nhịp 14:** break im lặng.
- **Ô nhịp 15:** quay lại đầy đủ.
- **Ô nhịp 17:** chuông FM và fade.
- Mỗi hành động có SFX riêng trong `EVENTS`.

## Nguồn của từng thông tin trên màn hình

| Thông tin | Nguồn |
|---|---|
| Tagline "Give AI agents the authority to deploy. Never the raw keys." | `README.md` (đầu file) |
| *Separate Authority from Possession* | `README.md` |
| Rủi ro: token sống lâu, toàn quyền tài khoản, lộ qua stdout / transcript | `README.md`, bảng so sánh (dòng 44–48) |
| Vòng đời Policy → Vault → Mint → Exec → Revoke / Scrub / Audit | `README.md` (sơ đồ, dòng 65–100) |
| Chặn `printenv` / `env` / `export` / `/proc/self/environ` | `internal/core/runner.go:147-154` |
| `allowed_scopes`, `allowed_permissions`, `max_ttl_seconds` | `internal/core/runner.go:63-66,165-209` |
| Khóa gốc chỉ nằm trong RAM của host | `README.md:76` |
| `[MINTRUN:REDACTED]` | `internal/core/runner.go:21` |
| `~/.mintrun/audit.jsonl`, các field `revoked`, `exit_code` | `README.md:182` và `AuditEntry` |
| Vault Keychain / 1Password / AES-256-GCM | `README.md:99` và `./mintrun plugin list` |
| Lệnh `mintrun exec -provider cloudflare -scope example.com -perms dns:write -ttl 300 -- npx wrangler deploy` | cú pháp CLI trong `README.md` |
| 100% Go stdlib, 0 dependencies, MCP server (`mintrun_exec`), plugin | `README.md:12,101,212` |

Token trên màn hình đều là giá trị giả, rõ ràng là giả (`FAKE-…`).
