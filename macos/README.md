# `mintrun` macOS Menu Bar App

`MintrunMenuBar.swift` is a single-file SwiftUI and AppKit menu bar app with no dependencies. It pairs with `mintrun watch`, which serves `<home>/app.sock` and the loopback dashboard, and talks to the watcher only through the dashboard's `/api/` routes.

## What It Shows

- **Menu bar icon:** the app runs as an accessory (no Dock icon). The icon is an SF Symbol that shows one state at a time, in this order:
  - `exclamationmark.triangle`: `mintrun watch` stopped. The menu offers **Try Again**.
  - `exclamationmark.shield.fill` and a count: requests are waiting for you.
  - `pause.circle`: requests are paused, and new ones are refused.
  - `bolt.shield`: commands are running.
  - `lock.shield`: watching for requests (dimmed while it starts).
- **Menu:** a status line, then **Pause Requests** or **Resume Requests**, then a **Waiting for You** section (one **Review** item per request) and a **Running** section (one **Stop** item per command), then **Find Sign-ins on This Computer…**, **Open Dashboard** (Command-D) and **Quit mintrun** (Command-Q).
- **Approval window:** one window per request, opened when the request arrives and closed quietly when it is answered elsewhere or expires. It shows the command, warnings for static mode and the `Hints:` labels, the semantic screen's risk when it is on, and the service, access, options, folder, reason, sender, device, sandbox, network, and credential lifetime. The sender's name is marked as not verified, because an MCP client reports its own. **Show full request** shows the whole `core.ApprovalText`.
- **Deny is the default:** Return and Esc deny, and closing the window denies. **Allow** stays disabled for a moment after the window opens, so a click or key meant for another window cannot land on it.
- **Stop:** asks first, then sends `POST /api/stop`, and `mintrun` ends the command's process group (a process that left the group keeps running).
- **Pause:** `POST /api/pause` creates or removes `<home>/paused`.
- **Find Sign-ins:** the app's first launch opens this window once (the `scanShown` default records it), and the menu opens it again. It runs `mintrun scan` and shows one row per result: a key the AWS or Google Cloud tool keeps, with **Add to mintrun**, a person's own sign-in, which needs its own setup, or a file `mintrun` could not read. **Add to mintrun** runs `mintrun scan -add <id>`, which copies the key into `mintrun`'s vault and leaves the tool's file as it is; when the vault already holds that key, the row says `mintrun` kept the one it has. **Technical Details** shows each row's id and file, the full text of any error, and the `mintrun init` command for each sign-in. The window never shows a secret, because `mintrun scan` never prints one.
- **Look:** both windows sit on Liquid Glass from edge to edge, as macOS 26 draws a menu bar app's windows (`onGlass` and `glassWindow`), with their content in grouped boxes and large glass buttons. Check a change in a live window capture (`screencapture -l<window id>`): an offscreen render draws no glass.

## How It Connects

- With `MINTRUN_WATCH_URL` set, the app uses that URL. Otherwise it starts `mintrun watch -http 127.0.0.1:0` itself (the binary from `MINTRUN_BIN`, else `mintrun` in the folder above the app's, else `mintrun` on `PATH`), reads the URL from the line it prints, and stops it on quit.
- The URL must be the whole `http://127.0.0.1:<port>/#<token>` line; the app refuses a URL without the `#token` fragment. The token goes in `X-Mintrun-Token` on every `/api/` request and never in a request URL, and every POST also sends `X-Mintrun-Watch: 1`.
- **Open Dashboard** opens that URL in your browser. The app never fetches the dashboard page itself.

## Build & Run

```bash
./macos/build.sh
./macos/MintrunMenuBar
```

Or run the watcher and its web dashboard without the menu bar app:

```bash
./mintrun watch
```
