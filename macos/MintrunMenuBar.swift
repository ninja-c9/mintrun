import AppKit
import Foundation
import SwiftUI

struct JevVerdict: Decodable {
    var risk: String?
    var labels: [String]?
    var severity: Int?
    var model: String?
}

struct WatchRequest: Decodable {
    var sandbox: Bool?
    var no_network: Bool?
    var provider: String?
    var scope: String?
    var permissions: [String]?
    var params: [String: String]?
    var command: [String]?
    var cwd: String?
    var purpose: String?
    var client: String?
    var via: String?
    var ttl_seconds: Int?
    var jev: JevVerdict?
}

struct WatchApproval: Decodable {
    var task: String
    var received_at: String?
    var text: String?
    var request: WatchRequest?
}

struct WatchAuditEntry: Decodable {
    var task: String?
    var ts: String?
    var provider: String?
    var scope: String?
    var command: [String]?
    var sandbox: Bool?
}

struct WatchActiveTask: Decodable {
    var task: String
    var entry: WatchAuditEntry?
}

// Go writes an empty slice as null, so every list is optional.
struct WatchState: Decodable {
    var paused: Bool?
    var approvals: [WatchApproval]?
    var active: [WatchActiveTask]?
}

// Fmt mirrors the dashboard's helpers in internal/builtin/watch.go, so both read a request the same way.
enum Fmt {
    static let hints = [
        "delete": "Deletes something", "force": "Forces or skips a safety check",
        "network-tool": "Uses a network tool", "encode": "Encodes data",
        "shell": "Runs a shell or redirects output", "external-url": "Calls a site outside the service",
    ]
    static let labels = [
        "exfil": "May send data out", "destructive": "May destroy data",
        "mismatch": "Does not match its reason", "injected": "Looks injected",
        "vague": "Reason is vague", "scope_creep": "Asks for more than it needs",
    ]
    static let via = ["mcp": "MCP", "cli": "Command line", "relay": "Team relay"]
    static let names = ["github": "GitHub", "aws": "AWS", "gcp": "Google Cloud", "cloudflare": "Cloudflare"]

    // show makes control and bidi characters visible, so agent text cannot hide or reorder what you read.
    static func show(_ s: String?, keepNL: Bool = false) -> String {
        var out = ""
        for u in (s ?? "").unicodeScalars {
            let v = u.value
            let hide = v <= 0x1f || (0x7f...0x9f).contains(v) || v == 0x61c || v == 0x200e || v == 0x200f
                || (0x202a...0x202e).contains(v) || (0x2066...0x2069).contains(v) || v == 0xfeff
            if hide && !(keepNL && v == 0x0a) {
                out += String(format: "\\u%04x", v)
            } else {
                out.unicodeScalars.append(u)
            }
        }
        return out
    }

    static func quote(_ s: String) -> String {
        guard let d = try? JSONSerialization.data(withJSONObject: s, options: [.fragmentsAllowed, .withoutEscapingSlashes]),
              let q = String(data: d, encoding: .utf8) else { return s }
        return q
    }

    static func argv(_ a: [String]?) -> String {
        (a ?? []).map { x in
            show(x.isEmpty || x.range(of: "[\\s\"'\\\\]", options: .regularExpression) != nil ? quote(x) : x)
        }.joined(separator: " ")
    }

    // svc names a provider alias type@account as "Type (account)".
    static func svc(_ p: String?, _ scope: String? = nil) -> String {
        let parts = (p ?? "").split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false)
        let t = String(parts[0])
        var out = names[t] ?? t
        if parts.count > 1 { out += " (\(parts[1]))" }
        if let scope, !scope.isEmpty { out += ", " + scope }
        return show(out)
    }

    static func from(_ client: String?, _ v: String?) -> String {
        [show(client), v.map { via[$0] ?? show($0) } ?? ""].filter { !$0.isEmpty }.joined(separator: " via ")
    }

    static func line(_ text: String?, _ key: String) -> String {
        for l in (text ?? "").components(separatedBy: "\n") where l.hasPrefix(key) {
            return String(l.dropFirst(key.count))
        }
        return ""
    }

    static func unquote(_ q: String) -> String {
        guard let d = q.data(using: .utf8),
              let s = try? JSONSerialization.jsonObject(with: d, options: .fragmentsAllowed) as? String else { return q }
        return s
    }

    static func short(_ s: String, _ n: Int = 40) -> String {
        s.count > n ? String(s.prefix(n - 1)) + "\u{2026}" : s
    }

    static func dur(_ sec: Int) -> String {
        let f = DateComponentsFormatter()
        f.allowedUnits = [.hour, .minute, .second]
        f.unitsStyle = .full
        f.maximumUnitCount = 2
        return f.string(from: TimeInterval(sec)) ?? "\(sec) seconds"
    }

    // date drops the fraction Go's RFC3339Nano may carry; "ago" needs no more than seconds.
    static func date(_ s: String?) -> Date? {
        guard let s else { return nil }
        return ISO8601DateFormatter().date(from: s.replacingOccurrences(of: "\\.[0-9]+", with: "", options: .regularExpression))
    }

    static func ago(_ d: Date?, now: Date = Date()) -> String {
        guard let d else { return "" }
        if now.timeIntervalSince(d) < 45 { return "just now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: d, relativeTo: now)
    }
}

@MainActor final class ApprovalModel: ObservableObject {
    let approval: WatchApproval
    @Published var sending = false
    @Published var error: String?
    var decide: @MainActor (Bool) -> Void = { _ in }
    init(_ a: WatchApproval) { approval = a }
}

struct ApprovalView: View {
    @ObservedObject var model: ApprovalModel
    @State private var armed = false

    var body: some View {
        let a = model.approval
        let r = a.request ?? WatchRequest()
        VStack(spacing: 14) {
            VStack(spacing: 4) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 40))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.tint)
                    .padding(.bottom, 6)
                    .accessibilityHidden(true)
                Text("Allow this command?").font(.title2.weight(.semibold))
                if let asked = Fmt.date(a.received_at) {
                    TimelineView(.everyMinute) { ctx in
                        Text("Asked " + Fmt.ago(asked, now: ctx.date)).foregroundStyle(.secondary)
                    }
                }
            }
            command(Fmt.argv(r.command))
            warnings(a, r)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
                let rows = facts(a, r)
                ForEach(rows.indices, id: \.self) { i in
                    GridRow {
                        Text(rows[i].0).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                        Text(rows[i].1).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quinary, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            DisclosureGroup("Show full request") {
                ScrollView {
                    Text(Fmt.show(a.text, keepNL: true))
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: 160)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if let e = model.error {
                Label(e, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
            }
            VStack(spacing: 10) {
                HStack(spacing: 10) {
                    Button { model.decide(true) } label: { Text("Allow").frame(maxWidth: .infinity) }
                        .buttonStyle(.glass)
                        .disabled(!armed || model.sending)
                    Button { model.decide(false) } label: { Text("Deny").frame(maxWidth: .infinity) }
                        .buttonStyle(.glassProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(model.sending)
                }
                .controlSize(.large)
                HStack(spacing: 6) {
                    if model.sending { ProgressView().controlSize(.small) }
                    Text("Closing this window denies the request.").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
        .onGlass(width: 460)
        // Allow waits a moment, so a click or key meant for another window cannot land on it.
        .task {
            try? await Task.sleep(for: .milliseconds(800))
            armed = true
        }
        .onChange(of: model.error) { _, e in
            if let e { AccessibilityNotification.Announcement(e).post() }
        }
    }

    @ViewBuilder private func command(_ cmd: String) -> some View {
        let text = Text(cmd.isEmpty ? "(no command)" : cmd)
            .font(.body.monospaced())
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
        Group {
            // ponytail: a fixed 96 pt box for long commands; measure the text if that proves too small.
            if cmd.count > 300 {
                ScrollView { text }.frame(height: 96)
            } else {
                text
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    @ViewBuilder private func warnings(_ a: WatchApproval, _ r: WatchRequest) -> some View {
        let isStatic = (r.permissions ?? []).contains("static") || r.params?["mode"] == "static"
        let hints = Fmt.line(a.text, "Hints: ").components(separatedBy: ", ").compactMap { Fmt.hints[$0] }
        let warns = (isStatic ? ["Static mode: uses the stored secret itself"] : []) + hints
        let risk = r.jev?.risk ?? ""
        if !warns.isEmpty || !risk.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(warns, id: \.self) { w in
                    Label {
                        Text(w)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                }
                if !risk.isEmpty {
                    let labels = (r.jev?.labels ?? []).compactMap { Fmt.labels[$0] }
                    let (symbol, color): (String, Color) = risk == "low" ? ("checkmark.circle.fill", .green)
                        : risk == "high" ? ("xmark.octagon.fill", .red) : ("exclamationmark.triangle.fill", .orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Label {
                            Text("Risk: " + Fmt.show(risk) + (labels.isEmpty ? "" : " \u{2014} " + labels.joined(separator: ", ")))
                        } icon: {
                            Image(systemName: symbol).foregroundStyle(color)
                        }
                        Text("From the optional semantic screen. It can only ask or deny, never allow.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func facts(_ a: WatchApproval, _ r: WatchRequest) -> [(String, String)] {
        let params = (r.params ?? [:]).keys.sorted().map { Fmt.show($0) + "=" + Fmt.show(r.params?[$0]) }
        let device = Fmt.line(a.text, "Device: ")
        let client = r.client.map { $0.isEmpty ? $0 : $0 + " (name not verified)" }
        let all: [(String, String)] = [
            ("Service", Fmt.svc(r.provider, r.scope)),
            ("Access", (r.permissions ?? []).map { Fmt.show($0) }.joined(separator: ", ")),
            ("Options", params.joined(separator: ", ")),
            ("Folder", (r.cwd ?? "").isEmpty ? "Not set (mintrun's own folder)" : Fmt.show(r.cwd)),
            ("Reason", (r.purpose ?? "").isEmpty ? "" : "\u{201C}" + Fmt.show(r.purpose) + "\u{201D}"),
            ("From", Fmt.from(client, r.via)),
            ("Device", device.isEmpty ? "" : Fmt.show(Fmt.unquote(device))),
            ("Sandbox", r.sandbox == true ? "On: it cannot read mintrun's folder or the keychain by path"
                : "Off: runs as you, with your files and keychain"),
            ("Network", r.no_network == true ? "Blocked" : "Open"),
            ("Credential", (r.ttl_seconds ?? 0) > 0 ? "Asked to last " + Fmt.dur(r.ttl_seconds ?? 0) : ""),
        ]
        return all.filter { !$0.1.isEmpty }
    }
}

// mintrunProcess runs the binary from MINTRUN_BIN, else mintrun in the folder above the app's, else
// mintrun on PATH.
func mintrunProcess(_ args: [String]) -> Process {
    let proc = Process()
    var bin = "mintrun"
    if let env = ProcessInfo.processInfo.environment["MINTRUN_BIN"], !env.isEmpty {
        bin = env
    } else {
        let selfDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        let repoBin = selfDir.deletingLastPathComponent().appendingPathComponent("mintrun").path
        if FileManager.default.isExecutableFile(atPath: repoBin) { bin = repoBin }
    }
    if bin.contains("/") {
        proc.executableURL = URL(fileURLWithPath: bin)
        proc.arguments = args
    } else {
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = [bin] + args
    }
    return proc
}

// runMintrun waits for one short mintrun command. Its output is a few KiB and its error one line,
// so reading stdout to the end before stderr cannot fill a pipe.
func runMintrun(_ args: [String]) async -> (status: Int32, out: Data, err: Data) {
    await Task.detached {
        let p = mintrunProcess(args)
        let out = Pipe(), err = Pipe()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = out
        p.standardError = err
        do { try p.run() } catch { return (-1, Data(), Data(error.localizedDescription.utf8)) }
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, o, e)
    }.value
}

// mintrunError is the {"error": …} line mintrun's fatal writes, or the raw stderr.
func mintrunError(_ r: (status: Int32, out: Data, err: Data)) -> String {
    if let j = try? JSONSerialization.jsonObject(with: r.err) as? [String: Any], let e = j["error"] as? String {
        return Fmt.show(e)
    }
    let s = String(decoding: r.err, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    return Fmt.show(s.isEmpty ? "mintrun exited with status \(r.status)" : s)
}

// ScanRow is one row of mintrun scan (cmd/mintrun/scan.go): a sign-in another tool keeps, or a file
// it could not read. It never holds a secret.
struct ScanRow: Decodable {
    var id: String?
    var provider: String
    var kind: String?
    var `where`: String
    var label: String?
    var temporary: Bool?
    var error: String?
}

@MainActor final class ScanModel: ObservableObject {
    enum Add: Equatable { case adding, added, held(String), failed(String) }
    @Published var rows: [ScanRow]?
    @Published var failure: String?
    @Published var adds: [String: Add] = [:]

    // scan keeps the rows even when mintrun exits 1, which it does when a row is an error.
    func scan() async {
        rows = nil
        failure = nil
        let r = await runMintrun(["scan"])
        if let rows = try? JSONDecoder().decode([ScanRow].self, from: r.out) {
            self.rows = rows
        } else {
            failure = mintrunError(r)
            rows = []
        }
    }

    // add copies a key row's secret into mintrun's vault. mintrun refuses a key it already holds
    // (cmd/mintrun/scan.go's "is already stored"), which is no failure: the held key still works.
    func add(_ id: String) async {
        adds[id] = .adding
        let r = await runMintrun(["scan", "-add", id])
        if r.status == 0 {
            adds[id] = .added
        } else {
            let e = mintrunError(r)
            adds[id] = e.contains(" is already stored") ? .held(e) : .failed(e)
        }
    }
}

struct ScanView: View {
    @ObservedObject var model: ScanModel
    var close: () -> Void = {}

    static let tools = [
        "github": "GitHub's command-line tool (gh)", "aws": "the AWS command-line tool (aws)",
        "gcp": "the Google Cloud command-line tool (gcloud)", "cloudflare": "Cloudflare's Wrangler tool",
    ]

    var body: some View {
        VStack(spacing: 16) {
            VStack(spacing: 4) {
                Image(systemName: "person.badge.key.fill")
                    .font(.system(size: 40))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.tint)
                    .padding(.bottom, 6)
                    .accessibilityHidden(true)
                Text("Sign-ins already on this computer").font(.title2.weight(.semibold))
                Text("mintrun looked in the files that GitHub, AWS, Google Cloud, and Cloudflare tools keep. It only reads them and changes nothing.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            content
            DisclosureGroup("Technical Details") {
                Text(details)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(.quinary, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 10) {
                Button { Task { await model.scan() } } label: { Text("Look Again").frame(maxWidth: .infinity) }
                    .buttonStyle(.glass)
                    .disabled(model.rows == nil || model.adds.values.contains(.adding))
                Button { close() } label: { Text("Done").frame(maxWidth: .infinity) }
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
        }
        .onGlass(width: 560)
        .task { await model.scan() }
        .onExitCommand { close() }
    }

    @ViewBuilder private var content: some View {
        Group {
            if let rows = model.rows {
                if let f = model.failure {
                    Label("mintrun could not look for sign-ins. Technical Details says why.", systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                        .padding(14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityLabel("mintrun could not look for sign-ins: " + f)
                } else if rows.isEmpty {
                    VStack(spacing: 4) {
                        Text("No sign-ins found").fontWeight(.medium)
                        Text("None of these tools is signed in on this computer: GitHub, AWS, Google Cloud, or Cloudflare's command-line tools.")
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(18)
                    .frame(maxWidth: .infinity)
                } else {
                    let list = VStack(alignment: .leading, spacing: 0) {
                        ForEach(rows.indices, id: \.self) { i in
                            // The line starts after the icon, as in System Settings.
                            if i > 0 { Divider().padding(.leading, 52) }
                            row(rows[i])
                        }
                    }
                    // ponytail: a fixed 300 pt box past five rows, like the approval window's command box.
                    if rows.count > 5 {
                        ScrollView { list }.defaultScrollAnchor(.top).frame(height: 300)
                    } else {
                        list
                    }
                }
            } else {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Looking for sign-ins\u{2026}").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 72)
            }
        }
        .background(.quinary, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    private func row(_ r: ScanRow) -> some View {
        let tool = Self.tools[r.provider] ?? Fmt.show(r.provider)
        let title = Fmt.svc(r.provider) + ((r.label ?? "").isEmpty ? "" : " (" + Fmt.show(r.label) + ")")
        let (symbol, color, detail): (String, Color, String) =
            r.error != nil ? ("exclamationmark.triangle.fill", .orange, "mintrun could not read a file from \(tool). Technical Details says why.")
            : r.kind == "key" ? ("key.fill", .accentColor, "A key in \(tool). Add a copy, and AI apps can use it without seeing it."
                + (r.temporary == true ? " Temporary: it stops working when it expires." : ""))
            : ("person.fill", .gray, "Your own sign-in in \(tool). mintrun does not lend sign-ins, so \(Fmt.svc(r.provider)) needs its own setup.")
        return HStack(alignment: .center, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 28, height: 28)
                .background(color.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).fontWeight(.medium)
                Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if let id = r.id, case .held = model.adds[id] {
                    Label("mintrun already has a key for \(Fmt.svc(r.provider)), so it kept that one.", systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let id = r.id, case .failed = model.adds[id] {
                    Label("Could not add it. Technical Details says why.", systemImage: "xmark.octagon.fill")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            if r.kind == "key", r.error == nil, let id = r.id {
                switch model.adds[id] {
                case .adding:
                    ProgressView().controlSize(.small)
                case .added:
                    Label("Added", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                case .held:
                    EmptyView()
                default:
                    Button(model.adds[id] == nil ? "Add to mintrun" : "Try Again") { Task { await model.add(id) } }
                        .buttonBorderShape(.capsule)
                        .disabled(model.rows == nil)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(minHeight: 44)
        .accessibilityElement(children: .combine)
    }

    private var details: String {
        guard let rows = model.rows else { return "Running mintrun scan\u{2026}" }
        if let f = model.failure { return "mintrun scan: " + f }
        var lines = rows.map { r in
            [r.id ?? r.provider, Fmt.show(r.where), r.error.map { Fmt.show($0) } ?? ""].filter { !$0.isEmpty }.joined(separator: "  ")
        }
        for (id, a) in model.adds.sorted(by: { $0.key < $1.key }) {
            switch a {
            case .held(let e), .failed(let e): lines.append("mintrun scan -add \(Fmt.show(id)): " + e)
            default: break
            }
        }
        let setups = Set(rows.filter { $0.kind == "signin" }.map(\.provider))
        for p in ["github", "aws", "gcp", "cloudflare"] where setups.contains(p) {
            lines.append("Set up \(Fmt.svc(p)): mintrun init \(p)")
        }
        return lines.isEmpty ? "mintrun scan found nothing." : lines.joined(separator: "\n")
    }
}

extension View {
    // onGlass lays a window's view on Liquid Glass from edge to edge, title bar included, as macOS 26 draws a
    // menu bar app's windows. The view itself stays below the title bar. Its window needs glassWindow.
    func onGlass(width: CGFloat) -> some View {
        padding(.horizontal, 24)
            .padding(.top, 4)
            .padding(.bottom, 24)
            .frame(width: width)
            .background { Color.clear.glassEffect(.regular, in: ConcentricRectangle()).ignoresSafeArea() }
    }
}

// glassWindow clears a titled window's background and title bar so the glass of its onGlass view shows through.
// The title stays set for the Window menu and VoiceOver.
@MainActor func glassWindow(_ w: NSWindow) {
    w.styleMask.insert(.fullSizeContentView)
    w.titlebarAppearsTransparent = true
    w.titleVisibility = .hidden
    w.isOpaque = false
    w.backgroundColor = .clear
}

// ApprovalPanel shows one request. Closing it, by its button or Esc, denies the request.
@MainActor final class ApprovalPanel: NSPanel, NSWindowDelegate {
    let task: String
    let model: ApprovalModel
    var decided = false
    var onDeny: @MainActor () -> Void = {}
    var onClose: @MainActor () -> Void = {}

    init(_ model: ApprovalModel) {
        self.model = model
        task = model.approval.task
        super.init(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        title = "mintrun"
        glassWindow(self)
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        level = .floating
        collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        delegate = self
        let host = NSHostingController(rootView: ApprovalView(model: model))
        host.sizingOptions = .preferredContentSize
        contentViewController = host
        setContentSize(host.view.fittingSize)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    override func cancelOperation(_ sender: Any?) { performClose(sender) }

    func windowWillClose(_ notification: Notification) {
        if !decided {
            decided = true
            onDeny()
        }
        onClose()
    }

    // finish closes the panel without sending anything: the request was answered or is gone.
    func finish() {
        decided = true
        close()
    }
}

@MainActor final class MintrunMenuBarDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private enum Phase { case starting, connected, failed }

    private var statusItem: NSStatusItem!
    private var watchProcess: Process?
    private var baseURL: URL?
    // dashboardURL is the URL mintrun watch printed, #token included; token goes on every request.
    private var dashboardURL: URL?
    private var token = ""
    private var envURL: String?
    private var pollTimer: Timer?
    private var polling = false
    private var failures = 0
    private var phase = Phase.starting
    private var state = WatchState()
    private var promptedTasks = Set<String>()
    private var panels: [String: ApprovalPanel] = [:]
    private var cascade = NSPoint.zero
    private var scanWindow: NSWindow?
    // An ephemeral session keeps request text out of the on-disk URL cache.
    private let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 3
        return URLSession(configuration: c)
    }()

    private var approvals: [WatchApproval] { state.approvals ?? [] }
    private var active: [WatchActiveTask] { state.active ?? [] }
    private var paused: Bool { state.paused ?? false }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        updateStatusItem()

        if let env = ProcessInfo.processInfo.environment["MINTRUN_WATCH_URL"], !env.isEmpty {
            envURL = env
            connect(env)
        } else {
            startWatchSubprocess()
        }
        // The first launch looks for sign-ins other tools keep, so setup starts from what is there.
        if !UserDefaults.standard.bool(forKey: "scanShown") {
            UserDefaults.standard.set(true, forKey: "scanShown")
            showScan()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        pollTimer?.invalidate()
        if let proc = watchProcess, proc.isRunning {
            proc.terminate()
            proc.waitUntilExit()
        }
    }

    private func startWatchSubprocess() {
        let proc = mintrunProcess(["watch", "-http", "127.0.0.1:0"])
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.standardError

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            guard let line = String(data: data, encoding: .utf8),
                  let range = line.range(of: "http://127\\.0\\.0\\.1:[0-9]+/#[A-Z2-7]+", options: .regularExpression) else { return }
            let urlStr = String(line[range])
            handle.readabilityHandler = nil
            DispatchQueue.main.async {
                MainActor.assumeIsolated { self?.connect(urlStr) }
            }
        }
        let id = ObjectIdentifier(proc)
        proc.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, let p = self.watchProcess, ObjectIdentifier(p) == id else { return }
                    self.fail()
                }
            }
        }

        do {
            try proc.run()
            watchProcess = proc
        } catch {
            FileHandle.standardError.write(Data("mintrun menu bar: could not start mintrun watch: \(error.localizedDescription)\n".utf8))
            fail()
        }
    }

    // connect takes http://127.0.0.1:<port>/#<token>. The token stays out of every request URL and
    // goes in the X-Mintrun-Token header, which every /api/ route requires.
    private func connect(_ raw: String) {
        guard var parts = URLComponents(string: raw), let frag = parts.fragment, !frag.isEmpty,
              let page = parts.url else {
            FileHandle.standardError.write(Data("mintrun menu bar: the dashboard URL must end in the #token that mintrun watch prints\n".utf8))
            fail()
            return
        }
        parts.fragment = nil
        token = frag
        dashboardURL = page
        baseURL = parts.url
        startPolling()
    }

    private func startPolling() {
        pollTimer?.invalidate()
        failures = 0
        pollState()
        let t = Timer(timeInterval: 0.75, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.pollState() }
        }
        RunLoop.main.add(t, forMode: .common)
        pollTimer = t
    }

    private func pollState() {
        guard let base = baseURL, !polling else { return }
        polling = true
        var req = URLRequest(url: base.appendingPathComponent("api/state"))
        req.setValue(token, forHTTPHeaderField: "X-Mintrun-Token")
        Task {
            defer { polling = false }
            do {
                let (data, resp) = try await session.data(for: req)
                guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
                let s = try JSONDecoder().decode(WatchState.self, from: data)
                guard pollTimer != nil else { return }
                failures = 0
                phase = .connected
                state = s
                updateUI()
            } catch {
                failures += 1
                if failures >= 4 && pollTimer != nil { fail() }
            }
        }
    }

    private func postAPI(_ path: String, body: [String: Any], done: @escaping @MainActor (String?) -> Void = { _ in }) {
        guard let base = baseURL else {
            done("mintrun watch is not connected")
            return
        }
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("1", forHTTPHeaderField: "X-Mintrun-Watch")
        req.setValue(token, forHTTPHeaderField: "X-Mintrun-Token")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        Task {
            var msg: String?
            do {
                let (data, resp) = try await session.data(for: req)
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                if !(200..<300).contains(code) {
                    let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                    msg = (j?["error"] as? String).map { Fmt.show($0) } ?? "mintrun watch answered \(code)"
                }
            } catch {
                msg = error.localizedDescription
            }
            done(msg)
            pollState()
        }
    }

    private func fail() {
        pollTimer?.invalidate()
        pollTimer = nil
        phase = .failed
        for p in panels.values { p.finish() }
        state = WatchState()
        promptedTasks.removeAll()
        updateUI()
    }

    private func updateUI() {
        updateStatusItem()
        let tasks = Set(approvals.map(\.task))
        for a in approvals where !promptedTasks.contains(a.task) {
            promptedTasks.insert(a.task)
            showPanel(a)
        }
        // A request answered elsewhere, or past its deadline, leaves the state: close its panel quietly.
        for (task, p) in panels where !tasks.contains(task) { p.finish() }
        promptedTasks.formIntersection(tasks)
    }

    private func updateStatusItem() {
        guard let button = statusItem.button else { return }
        let symbol: String
        let tip: String
        var title = ""
        switch phase {
        case .failed:
            (symbol, tip) = ("exclamationmark.triangle", "mintrun watch stopped")
        case .starting:
            (symbol, tip) = ("lock.shield", "mintrun is starting")
        case .connected where !approvals.isEmpty:
            let n = approvals.count
            (symbol, tip) = ("exclamationmark.shield.fill", n == 1 ? "1 request is waiting for you" : "\(n) requests are waiting for you")
            title = "\(n)"
        case .connected where paused:
            (symbol, tip) = ("pause.circle", "Paused: new requests are refused")
        case .connected where !active.isEmpty:
            let n = active.count
            (symbol, tip) = ("bolt.shield", n == 1 ? "1 command is running" : "\(n) commands are running")
        case .connected:
            (symbol, tip) = ("lock.shield", "mintrun is watching for requests")
        }
        button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: tip)
        button.imagePosition = title.isEmpty ? .imageOnly : .imageLeading
        button.title = title
        button.toolTip = tip
        button.appearsDisabled = phase == .starting
    }

    // The menu is built when it opens, so it never changes under the pointer.
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let status: String
        switch phase {
        case .starting: status = "Starting\u{2026}"
        case .failed: status = "mintrun watch stopped"
        case .connected: status = paused ? "Paused: new requests are refused" : "Watching for requests"
        }
        let head = NSMenuItem(title: status, action: nil, keyEquivalent: "")
        head.isEnabled = false
        menu.addItem(head)
        if phase == .failed { menu.addItem(item("Try Again", #selector(retry))) }
        if phase == .connected { menu.addItem(item(paused ? "Resume Requests" : "Pause Requests", #selector(togglePause))) }

        if !approvals.isEmpty {
            menu.addItem(.separator())
            menu.addItem(.sectionHeader(title: "Waiting for You"))
            for a in approvals {
                let it = item("Review \u{201C}\(Fmt.short(Fmt.argv(a.request?.command)))\u{201D}\u{2026}", #selector(review(_:)))
                it.subtitle = Fmt.svc(a.request?.provider, a.request?.scope)
                it.representedObject = a.task
                menu.addItem(it)
            }
        }
        if !active.isEmpty {
            menu.addItem(.separator())
            menu.addItem(.sectionHeader(title: "Running"))
            for t in active {
                let e = t.entry ?? WatchAuditEntry()
                let it = item("Stop \u{201C}\(Fmt.short(Fmt.argv(e.command)))\u{201D}\u{2026}", #selector(stop(_:)))
                let started = Fmt.ago(Fmt.date(e.ts))
                it.subtitle = Fmt.svc(e.provider) + (e.sandbox == true ? ", sandboxed" : "") + (started.isEmpty ? "" : ", started " + started)
                it.representedObject = t.task
                menu.addItem(it)
            }
        }

        menu.addItem(.separator())
        menu.addItem(item("Find Sign-ins on This Computer\u{2026}", #selector(showScan)))
        if dashboardURL != nil { menu.addItem(item("Open Dashboard", #selector(openDashboard), "d")) }
        menu.addItem(item("Quit mintrun", #selector(quitApp), "q"))
    }

    private func item(_ title: String, _ action: Selector, _ key: String = "") -> NSMenuItem {
        let it = NSMenuItem(title: title, action: action, keyEquivalent: key)
        it.target = self
        return it
    }

    private func showPanel(_ a: WatchApproval) {
        NSApp.activate()
        if let p = panels[a.task] {
            p.makeKeyAndOrderFront(nil)
            return
        }
        let model = ApprovalModel(a)
        let p = ApprovalPanel(model)
        let task = a.task
        model.decide = { [weak self, weak p, weak model] allow in
            guard let self, let p, let model, !p.decided else { return }
            model.sending = true
            model.error = nil
            self.postAPI("api/decide", body: ["task": task, "decision": allow ? "allow" : "deny"]) { err in
                model.sending = false
                if let err { model.error = "Could not send: " + err } else { p.finish() }
            }
        }
        p.onDeny = { [weak self] in self?.postAPI("api/decide", body: ["task": task, "decision": "deny"]) }
        p.onClose = { [weak self] in self?.panels[task] = nil }
        if panels.isEmpty {
            p.center()
            cascade = NSPoint(x: p.frame.minX, y: p.frame.maxY)
        }
        cascade = p.cascadeTopLeft(from: cascade)
        panels[task] = p
        p.makeKeyAndOrderFront(nil)
        p.orderFrontRegardless()
    }

    private func alert(_ title: String, _ info: String) {
        NSApp.activate()
        let a = NSAlert()
        a.messageText = title
        a.informativeText = info
        a.runModal()
    }

    @objc private func retry() {
        phase = .starting
        updateStatusItem()
        if let env = envURL {
            connect(env)
            return
        }
        if let old = watchProcess {
            watchProcess = nil
            if old.isRunning {
                old.terminate()
                old.waitUntilExit()
            }
        }
        startWatchSubprocess()
    }

    @objc private func togglePause() {
        let to = !paused
        postAPI("api/pause", body: ["paused": to]) { [weak self] err in
            if let err { self?.alert(to ? "Could not pause requests" : "Could not resume requests", err) }
        }
    }

    @objc private func review(_ sender: NSMenuItem) {
        guard let task = sender.representedObject as? String,
              let a = approvals.first(where: { $0.task == task }) else { return }
        showPanel(a)
    }

    // Stop was chosen on purpose, so the alert keeps it as the default button (HIG: no destructive
    // style for the action a person deliberately chose).
    @objc private func stop(_ sender: NSMenuItem) {
        guard let task = sender.representedObject as? String else { return }
        NSApp.activate()
        let a = NSAlert()
        a.messageText = "Stop this command?"
        a.informativeText = "mintrun ends it and everything it started."
        a.addButton(withTitle: "Stop")
        a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        postAPI("api/stop", body: ["task": task]) { [weak self] err in
            if let err { self?.alert("Could not stop the command", err) }
        }
    }

    // showScan brings an open scan window forward, or opens a new one, which scans again.
    @objc private func showScan() {
        NSApp.activate()
        if let w = scanWindow, w.isVisible {
            w.makeKeyAndOrderFront(nil)
            return
        }
        let w = NSWindow(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        w.title = "Find Sign-ins"
        glassWindow(w)
        w.isReleasedWhenClosed = false
        let host = NSHostingController(rootView: ScanView(model: ScanModel()) { [weak w] in w?.close() })
        host.sizingOptions = .preferredContentSize
        w.contentViewController = host
        w.setContentSize(host.view.fittingSize)
        w.center()
        scanWindow = w
        w.makeKeyAndOrderFront(nil)
        w.orderFrontRegardless()
    }

    @objc private func openDashboard() {
        guard let url = dashboardURL else { return }
        NSWorkspace.shared.open(url)
    }

    @objc private func quitApp() {
        NSApp.terminate(nil)
    }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = MintrunMenuBarDelegate()
    app.delegate = delegate
    app.run()
}
