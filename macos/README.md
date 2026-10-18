# `mintrun` macOS Menu Bar Companion (`app.sock`)

`MintrunMenuBar.swift` is a single-file, zero-dependency native macOS `NSStatusBar` companion app that pairs with `mintrun watch` over `~/.mintrun/app.sock`.

## Features

- **Menu Bar Status Item (`🔒 mintrun`):** Runs as an `.accessory` app (no Dock icon), displaying enclave status (`Active`, `Paused`, pending approval count, or active running task count).
- **Human-in-the-Loop Approvals:** Prompts with a native `NSAlert` showing the full `core.ApprovalText` (`Sandbox: on|off`, `Network: blocked|open`, and every quoted agent field). **Deny** is always the default button (Return/Esc denies).
- **Live Task Tracking & `Stop` (`SIGKILL`):** Lists running blind child processes and sends `{"type":"stop"}` over `app.sock` when clicked.
- **Emergency Pause Toggle:** Creates or removes `~/.mintrun/paused` via `POST /api/pause` (`X-Mintrun-Watch: 1`).
- **Localhost Web Dashboard:** Opens the `mintrun watch` web dashboard (`http://127.0.0.1:<port>`) in your browser.

## Build & Run

```bash
./macos/build.sh
./macos/MintrunMenuBar
```

Or run the cross-platform CLI/web daemon directly without the macOS menu bar wrapper:

```bash
./mintrun watch
```
