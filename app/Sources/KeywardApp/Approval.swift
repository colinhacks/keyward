import SwiftUI
import AppKit

/// Context for one pending signature, sent by the daemon.
struct PendingSignature: Codable {
    var headline: String
    var app: String?
    var appBundle: String?
    var process: String?
    var key: String?
    var fingerprint: String?
    var host: String?
    var repo: String?
    var branch: String?
    var subject: String?
    var command: String?
    var script: Bool?
    var chain: [String]
    var session: String?
    var directory: String?
    var remote: String?
    var commits: [String]?
    var commitCount: Int?
    var stat: String?
    var upstream: String?

    var isPush: Bool { commitCount != nil || !(commits ?? []).isEmpty }
}

enum CardMetrics {
    static let pad: CGFloat = 24
    static let gap: CGFloat = 20
    static let baseDetail: CGFloat = 470
    /// A script needs room to wrap rather than be cut off mid-pipeline.
    static let wideDetail: CGFloat = 660

    static func detailWidth(for ctx: PendingSignature) -> CGFloat {
        if let c = ctx.command, ApprovalView.isMultilineCommand(c) { return wideDetail }
        if ctx.isPush { return 560 }
        return baseDetail
    }
}

/// The card the system Touch ID sheet docks into.
///
/// The sheet belongs to `coreautha`, sits at window layer 1000, and cannot be
/// restyled, reparented or moved — so instead of fighting it, the card is laid
/// out *around* it: details on the left, and a reserved slot on the right of
/// exactly the sheet's dimensions. The panel finds the sheet's real frame at
/// runtime and positions itself so the sheet lands in that slot.
///
/// The rows read in the order of the decision: what leaves, the command that
/// sends it, where from, who asked, with which key. One rule between every
/// row, one separator style, nothing said twice.
struct ApprovalView: View {
    let ctx: PendingSignature
    let sheetSize: CGSize
    /// The commit list is collapsed to a one-line summary until asked for.
    var expanded: Bool = false
    var onToggle: () -> Void = {}

    var body: some View {
        HStack(alignment: .top, spacing: CardMetrics.gap) {
            details
                .frame(width: CardMetrics.detailWidth(for: ctx), alignment: .leading)
            // The slot. Empty on purpose — the system draws into it. Pinned to
            // the top so a card that grew for a long script still lines up.
            VStack(spacing: 0) {
                Color.clear.frame(width: sheetSize.width, height: sheetSize.height)
                Spacer(minLength: 0)
            }
        }
        .padding(CardMetrics.pad)
        .background(
            ZStack {
                VisualEffect(material: .hudWindow)
                Color.black.opacity(0.55)
            }
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .strokeBorder(.white.opacity(0.13), lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.55), radius: 40, y: 16)
        )
        .preferredColorScheme(.dark)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                if let b = ctx.appBundle, let icon = iconFor(b) {
                    Image(nsImage: icon).resizable().frame(width: 34, height: 34)
                }
                Text(ctx.headline)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(.bottom, 10)

            if let c = ctx.command, isMultiline(c) {
                scriptBlock(c).padding(.bottom, 11)
            }

            ForEach(Array(rows.enumerated()), id: \.offset) { idx, row in
                if idx > 0 {
                    Divider().overlay(.white.opacity(0.10))
                        .padding(.vertical, 9)
                }
                switch row {
                case .field(let f): block(f)
                case .changes: changesBlock
                }
            }
        }
        .frame(minHeight: sheetSize.height, alignment: .center)
    }

    private struct Field: Hashable {
        let label: String
        let value: String
        var mono: Bool = true
        var lines: Int = 1
    }

    private enum Row {
        case field(Field)
        case changes
    }

    /// One row per fact. Everything else — fingerprint, raw session id, the
    /// untrimmed process chain — lives in the app window, where there is room.
    private var rows: [Row] {
        var out: [Row] = []
        if let s = ctx.subject { out.append(.field(Field(label: "Commit", value: s, mono: false, lines: 2))) }
        if ctx.isPush { out.append(.changes) }
        // A multi-line script gets its own block above, not a squashed row.
        if let c = ctx.command, !isMultiline(c) { out.append(.field(Field(label: "Command", value: c, lines: 2))) }
        if let d = ctx.directory { out.append(.field(Field(label: "Directory", value: d, lines: 2))) }
        // The headline already names the host or repo; repeating either is noise.
        if let h = ctx.host, !ctx.isPush, !ctx.headline.contains(h) {
            out.append(.field(Field(label: "Server", value: h)))
        }
        if let by = requestedBy { out.append(.field(Field(label: "Requested by", value: by, mono: false, lines: 2))) }
        if let k = ctx.key { out.append(.field(Field(label: "Key", value: k))) }
        return out
    }

    /// The chain as a breadcrumb, outermost first, with the session title on
    /// the link that owns it. The app name is only prepended when it adds a
    /// step the chain does not already show.
    private var requestedBy: String? {
        var steps: [String] = []
        for name in ctx.chain {
            let n = name.lowercased()
            if n == "disclaimer" { continue }
            if steps.last?.lowercased() == n { continue }
            steps.append(name)
        }
        if let s = ctx.session, let i = steps.firstIndex(where: { $0.lowercased() == "claude" }) {
            steps[i] = "claude — “\(s)”"
        }
        if let app = ctx.app, steps.first?.lowercased() != app.lowercased() {
            steps.insert(app, at: 0)
        }
        if steps.count > 7 {
            steps = Array(steps.prefix(3)) + ["…"] + steps.suffix(3)
        }
        return steps.isEmpty ? nil : steps.joined(separator: "  ›  ")
    }

    // MARK: - Changes (push)

    static let commitMaxLines = 12

    private var changesSummary: String {
        var parts: [String] = []
        if let n = ctx.commitCount {
            parts.append(ctx.upstream == nil ? "new branch, \(n) commit\(n == 1 ? "" : "s")"
                                             : "\(n) commit\(n == 1 ? "" : "s")")
        }
        if let s = ctx.stat { parts.append(s) }
        return parts.isEmpty ? "nothing to send" : parts.joined(separator: "  ·  ")
    }

    private var changesBlock: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("CHANGES")
                .font(.system(size: 9.5, weight: .semibold))
                .tracking(0.7)
                .foregroundStyle(.white.opacity(0.40))
            HStack(spacing: 8) {
                Text(changesSummary)
                    .font(.system(size: 13.5))
                    .foregroundStyle(.white)
                if !(ctx.commits ?? []).isEmpty {
                    Button(action: onToggle) {
                        Text(expanded ? "hide commits" : "show commits")
                            .font(.system(size: 11.5))
                            .foregroundStyle(.white.opacity(0.6))
                            .padding(.horizontal, 8).padding(.vertical, 2)
                            .background(RoundedRectangle(cornerRadius: 5).fill(.white.opacity(0.08)))
                    }
                    .buttonStyle(.plain)
                }
            }
            if expanded, let commits = ctx.commits, !commits.isEmpty {
                let shown = Array(commits.prefix(Self.commitMaxLines))
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(shown.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 11.5, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.tail)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if let n = ctx.commitCount, n > shown.count {
                        Text("… \(n - shown.count) more")
                            .font(.system(size: 10.5))
                            .foregroundStyle(.white.opacity(0.45))
                    }
                }
                .padding(9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(.black.opacity(0.38))
                        .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous)
                            .strokeBorder(.white.opacity(0.08), lineWidth: 1))
                )
                .padding(.top, 6)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Scripts

    static let scriptMaxLines = 10

    static func isMultilineCommand(_ c: String) -> Bool {
        c.contains("\n") || c.count > 72
    }
    private func isMultiline(_ c: String) -> Bool { Self.isMultilineCommand(c) }

    struct CodeLine: Identifiable {
        let id: Int
        let text: String
        let comment: Bool
    }

    /// Section echoes become headings; everything else keeps its shell shape.
    static func codeLines(_ raw: String) -> [CodeLine] {
        var out: [CodeLine] = []
        for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
            let l = String(line)
            if let sec = ShellHighlighter.sectionTitle(l) {
                out.append(CodeLine(id: out.count, text: "# " + sec.title, comment: true))
                if !sec.rest.isEmpty {
                    out.append(CodeLine(id: out.count, text: sec.rest, comment: false))
                }
                continue
            }
            out.append(CodeLine(id: out.count, text: l, comment: false))
        }
        return out
    }

    /// The actual work, when it arrived as a script rather than a command.
    private func scriptBlock(_ raw: String) -> some View {
        let all = Self.codeLines(raw)
        let shown = Array(all.prefix(Self.scriptMaxLines))
        let hidden = all.count - shown.count
        return VStack(alignment: .leading, spacing: 5) {
            Text((ctx.script == true ? "SCRIPT" : "COMMAND")
                 + (all.count > 1 ? " · \(all.count) LINES" : ""))
                .font(.system(size: 9.5, weight: .semibold))
                .tracking(0.7)
                .foregroundStyle(.white.opacity(0.40))
            VStack(alignment: .leading, spacing: 3) {
                ForEach(shown) { line in
                    Text(ShellHighlighter.attributed(line.text, comment: line.comment))
                        .font(.system(size: 11.5, design: .monospaced))
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                if hidden > 0 {
                    Text("… \(hidden) more line\(hidden == 1 ? "" : "s")")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.white.opacity(0.45))
                        .padding(.top, 3)
                }
            }
            .padding(11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(.black.opacity(0.38))
                    .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .strokeBorder(.white.opacity(0.08), lineWidth: 1))
            )
        }
        .textSelection(.enabled)
    }

    // MARK: - Sizing

    /// The panel needs the height before the view exists, so it is computed
    /// from the same numbers the layout uses rather than measured afterwards.
    static func preferredHeight(for ctx: PendingSignature, sheetHeight: CGFloat, expanded: Bool) -> CGFloat {
        var h: CGFloat = 44                       // header
        if let c = ctx.command, isMultilineCommand(c) {
            let width = CardMetrics.detailWidth(for: ctx) - 22
            let perLine = max(20.0, Double(width) / 6.9)   // 11.5pt monospace
            let all = codeLines(c)
            let shown = all.prefix(scriptMaxLines)
            let visual = shown.reduce(0.0) { acc, l in
                acc + Double(min(3, max(1, Int(ceil(Double(l.text.count) / perLine)))))
            }
            h += 13 + 5 + 22 + CGFloat(visual) * 17 + (all.count > shown.count ? 18 : 0) + 11
        }
        var rows = 0
        if ctx.subject != nil { rows += 1 }
        if ctx.isPush { rows += 1 }
        if let c = ctx.command, !isMultilineCommand(c) { rows += 1 }
        if ctx.directory != nil { rows += 1 }
        if let hst = ctx.host, !ctx.isPush, !ctx.headline.contains(hst) { rows += 1 }
        rows += 1                                  // requested by
        if ctx.key != nil { rows += 1 }
        h += CGFloat(rows) * 34 + CGFloat(max(0, rows - 1)) * 19   // blocks + dividers
        if expanded, let commits = ctx.commits, !commits.isEmpty {
            let shown = min(commits.count, commitMaxLines)
            h += 6 + 18 + CGFloat(shown) * 17 + ((ctx.commitCount ?? 0) > shown ? 16 : 0)
        }
        return max(sheetHeight, h)
    }

    private func block(_ f: Field) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(f.label.uppercased())
                .font(.system(size: 9.5, weight: .semibold))
                .tracking(0.7)
                .foregroundStyle(.white.opacity(0.40))
            Text(f.value)
                .font(f.mono ? .system(size: 13, design: .monospaced)
                             : .system(size: 13.5))
                .foregroundStyle(.white)
                .lineLimit(f.lines)
                .truncationMode(.middle)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func iconFor(_ bundle: String) -> NSImage? {
        FileManager.default.fileExists(atPath: bundle)
            ? NSWorkspace.shared.icon(forFile: bundle) : nil
    }
}

/// The same blur the system dialogs are built from.
struct VisualEffect: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = material
        v.blendingMode = .behindWindow
        v.state = .active
        return v
    }
    func updateNSView(_ v: NSVisualEffectView, context: Context) { v.material = material }
}
