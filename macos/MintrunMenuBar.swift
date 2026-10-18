import AppKit
import Foundation

struct WatchApproval: Decodable {
    let task: String
    let received_at: String
    let text: String
}

struct WatchAuditEntry: Decodable {
    let task: String?
    let provider: String
    let scope: String?
    let command: [String]?
    let outcome: String?
    let sandbox: Bool?
    let no_network: Bool?
}

struct WatchActiveTask: Decodable {
    let task: String
    let entry: WatchAuditEntry
}

struct WatchState: Decodable {
    let paused: Bool
    let approvals: [WatchApproval]
    let active: [WatchActiveTask]
    let audit: [WatchAuditEntry]?
}

final class MintrunMenuBarDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var watchProcess: Process?
    private var baseURL: URL?
    private var pollTimer: Timer?
    private var lastState = WatchState(paused: false, approvals: [], active: [], audit: [])
    private var promptedTasks = Set<String>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🔒 mintrun"
        rebuildMenu()

        if let envURL = ProcessInfo.processInfo.environment["MINTRUN_WATCH_URL"],
           let url = URL(string: envURL) {
            baseURL = url
            startPolling()
        } else {
            startWatchSubprocess()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        pollTimer?.invalidate()
        if let proc = watchProcess, proc.isRunning {
            proc.terminate()
            proc.waitUntilExit()
        }
    }

    private func resolveMintrunBinary() -> String {
        if let envBin = ProcessInfo.processInfo.environment["MINTRUN_BIN"], !envBin.isEmpty {
            return envBin
        }
        let selfDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        let repoBin = selfDir.deletingLastPathComponent().appendingPathComponent("mintrun").path
        if FileManager.default.isExecutableFile(atPath: repoBin) {
            return repoBin
        }
        return "mintrun"
    }

    private func startWatchSubprocess() {
        let proc = Process()
        let bin = resolveMintrunBinary()
        if bin.contains("/") {
            proc.executableURL = URL(fileURLWithPath: bin)
            proc.arguments = ["watch", "-http", "127.0.0.1:0"]
        } else {
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            proc.arguments = [bin, "watch", "-http", "127.0.0.1:0"]
        }
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.standardError

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let line = String(data: data, encoding: .utf8) else { return }
            if let range = line.range(of: "http://127.0.0.1:[0-9]+", options: .regularExpression) {
                let urlStr = String(line[range])
                if let url = URL(string: urlStr) {
                    DispatchQueue.main.async {
                        self?.baseURL = url
                        self?.startPolling()
                    }
                    handle.readabilityHandler = nil
                }
            }
        }

        do {
            try proc.run()
            watchProcess = proc
        } catch {
            statusItem.button?.title = "⚠️ mintrun"
        }
    }

    private func startPolling() {
        pollState()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.75, repeats: true) { [weak self] _ in
            self?.pollState()
        }
    }

    private func pollState() {
        guard let base = baseURL else { return }
        let url = base.appendingPathComponent("api/state")
        URLSession.shared.dataTask(with: url) { [weak self] data, _, err in
            guard let self = self, err == nil, let data = data,
                  let state = try? JSONDecoder().decode(WatchState.self, from: data) else {
                return
            }
            DispatchQueue.main.async {
                self.lastState = state
                self.updateUI()
            }
        }.resume()
    }

    private func postAPI(_ path: String, body: [String: Any]) {
        guard let base = baseURL else { return }
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("1", forHTTPHeaderField: "X-Mintrun-Watch")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: req) { [weak self] _, _, _ in
            DispatchQueue.main.async {
                self?.pollState()
            }
        }.resume()
    }

    private func updateUI() {
        if lastState.paused {
            statusItem.button?.title = "⏸ mintrun (Paused)"
        } else if !lastState.approvals.isEmpty {
            statusItem.button?.title = "⚠️ mintrun (\(lastState.approvals.count))"
        } else if !lastState.active.isEmpty {
            statusItem.button?.title = "🟢 mintrun (\(lastState.active.count) running)"
        } else {
            statusItem.button?.title = "🔒 mintrun"
        }
        rebuildMenu()

        for approval in lastState.approvals where !promptedTasks.contains(approval.task) {
            promptedTasks.insert(approval.task)
            showApprovalAlert(approval)
        }
    }

    private func showApprovalAlert(_ approval: WatchApproval) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "mintrun Approval Request"
        alert.informativeText = approval.text
        // Rule 4 & 31: Deny is always the first (default Return) button.
        alert.addButton(withTitle: "Deny")
        alert.addButton(withTitle: "Allow")
        alert.alertStyle = .warning
        let resp = alert.runModal()
        let decision = (resp == .alertSecondButtonReturn) ? "allow" : "deny"
        postAPI("api/decide", body: ["task": approval.task, "decision": decision])
    }

    private func rebuildMenu() {
        let menu = NSMenu()
        let statusTitle = lastState.paused ? "Status: PAUSED (all exec denied)" : "Status: Active (listening on app.sock)"
        let statusHeader = NSMenuItem(title: statusTitle, action: nil, keyEquivalent: "")
        statusHeader.isEnabled = false
        menu.addItem(statusHeader)

        let pauseTitle = lastState.paused ? "Resume Executions" : "Pause All Executions"
        let pauseItem = NSMenuItem(title: pauseTitle, action: #selector(togglePause), keyEquivalent: "p")
        pauseItem.target = self
        menu.addItem(pauseItem)
        menu.addItem(NSMenuItem.separator())

        let appHeader = NSMenuItem(title: "Pending Approvals (\(lastState.approvals.count))", action: nil, keyEquivalent: "")
        appHeader.isEnabled = false
        menu.addItem(appHeader)
        if lastState.approvals.isEmpty {
            let none = NSMenuItem(title: "  None", action: nil, keyEquivalent: "")
            none.isEnabled = false
            menu.addItem(none)
        } else {
            for a in lastState.approvals {
                let item = NSMenuItem(title: "  Review Request \(a.task.prefix(8))…", action: #selector(reviewApproval(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = a.task
                menu.addItem(item)
            }
        }
        menu.addItem(NSMenuItem.separator())

        let actHeader = NSMenuItem(title: "Running Tasks (\(lastState.active.count))", action: nil, keyEquivalent: "")
        actHeader.isEnabled = false
        menu.addItem(actHeader)
        if lastState.active.isEmpty {
            let none = NSMenuItem(title: "  None", action: nil, keyEquivalent: "")
            none.isEnabled = false
            menu.addItem(none)
        } else {
            for t in lastState.active {
                let cmd = (t.entry.command ?? []).joined(separator: " ")
                let item = NSMenuItem(title: "  Stop [\(t.entry.provider)] \(cmd.prefix(36))", action: #selector(stopTask(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = t.task
                menu.addItem(item)
            }
        }
        menu.addItem(NSMenuItem.separator())

        if baseURL != nil {
            let openItem = NSMenuItem(title: "Open Web Dashboard…", action: #selector(openDashboard), keyEquivalent: "d")
            openItem.target = self
            menu.addItem(openItem)
        }
        let quitItem = NSMenuItem(title: "Quit mintrun Menu Bar", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu
    }

    @objc private func togglePause() {
        postAPI("api/pause", body: ["paused": !lastState.paused])
    }

    @objc private func reviewApproval(_ sender: NSMenuItem) {
        guard let task = sender.representedObject as? String,
              let approval = lastState.approvals.first(where: { $0.task == task }) else { return }
        showApprovalAlert(approval)
    }

    @objc private func stopTask(_ sender: NSMenuItem) {
        guard let task = sender.representedObject as? String else { return }
        postAPI("api/stop", body: ["task": task])
    }

    @objc private func openDashboard() {
        guard let url = baseURL else { return }
        NSWorkspace.shared.open(url)
    }

    @objc private func quitApp() {
        NSApp.terminate(nil)
    }
}

let app = NSApplication.shared
let delegate = MintrunMenuBarDelegate()
app.delegate = delegate
app.run()
