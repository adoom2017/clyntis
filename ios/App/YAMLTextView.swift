import SwiftUI
import UIKit

/// A plain-text editor for configuration YAML that tints one line red, the
/// syntax error the core found. Smart quotes and dashes are off: they break YAML.
struct YAMLTextView: UIViewRepresentable {
    @Binding var text: String
    /// 1-based line to mark, or nil.
    var errorLine: Int?
    /// Bumped to move the cursor to `errorLine` and scroll it into view.
    var revealRequest = 0

    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        view.delegate = context.coordinator
        view.font = .monospacedSystemFont(ofSize: UIFont.preferredFont(forTextStyle: .footnote).pointSize,
                                          weight: .regular)
        view.adjustsFontForContentSizeCategory = true
        view.backgroundColor = .clear
        view.textColor = .label
        view.autocapitalizationType = .none
        view.autocorrectionType = .no
        view.spellCheckingType = .no
        view.smartQuotesType = .no
        view.smartDashesType = .no
        view.smartInsertDeleteType = .no
        view.keyboardType = .asciiCapable
        view.alwaysBounceVertical = true
        view.keyboardDismissMode = .interactive
        view.textContainerInset = UIEdgeInsets(top: 8, left: 4, bottom: 8, right: 4)
        view.accessibilityLabel = "YAML 配置"
        return view
    }

    func updateUIView(_ view: UITextView, context: Context) {
        context.coordinator.text = $text
        if view.text != text { view.text = text }
        mark(view)
        if revealRequest != context.coordinator.revealed {
            context.coordinator.revealed = revealRequest
            if let range = lineRange(in: view.text) {
                view.becomeFirstResponder()
                view.selectedRange = NSRange(location: range.location, length: 0)
                view.scrollRangeToVisible(range)
            }
        }
        view.accessibilityValue = errorLine.map { "第 \($0) 行有格式错误" }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    /// Re-tints in place so the selection and scroll position stay put.
    private func mark(_ view: UITextView) {
        let storage = view.textStorage
        let whole = NSRange(location: 0, length: storage.length)
        storage.beginEditing()
        storage.removeAttribute(.backgroundColor, range: whole)
        if let range = lineRange(in: view.text) {
            storage.addAttribute(.backgroundColor, value: UIColor.systemRed.withAlphaComponent(0.22), range: range)
        }
        storage.endEditing()
    }

    /// The error line's range, newline included so an empty line still shows.
    private func lineRange(in text: String) -> NSRange? {
        guard let errorLine, errorLine > 0 else { return nil }
        let string = text as NSString
        var start = 0
        for _ in 1..<errorLine {
            let newline = string.range(of: "\n", range: NSRange(location: start, length: string.length - start))
            guard newline.location != NSNotFound else { return nil }
            start = newline.location + 1
        }
        let end = string.range(of: "\n", range: NSRange(location: start, length: string.length - start))
        let length = (end.location == NSNotFound ? string.length : end.location + 1) - start
        return NSRange(location: start, length: length)
    }

    final class Coordinator: NSObject, UITextViewDelegate {
        var text: Binding<String>
        var revealed = 0
        init(text: Binding<String>) { self.text = text }
        func textViewDidChange(_ view: UITextView) { text.wrappedValue = view.text }
    }
}
