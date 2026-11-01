import Foundation

/// The interface language. The choice is kept in the App Group so the
/// tunnel's messages follow it too. Text is written in Chinese in the source
/// and looked up in `englishText` when English is in effect.
enum Localization {
    static let key = "language"
    /// One instance per process; reading it is an in-memory lookup.
    static let defaults: UserDefaults = {
        let group = Bundle.main.object(forInfoDictionaryKey: "ClyntisAppGroup") as? String
        return group.flatMap(UserDefaults.init(suiteName:)) ?? .standard
    }()

    /// `system`, `zh` or `en`.
    static var setting: String {
        get { defaults.string(forKey: key) ?? "system" }
        set { defaults.set(newValue, forKey: key) }
    }

    /// `zh` or `en`: a chosen language, else the first preferred system
    /// language we have, else English.
    static func resolved(_ setting: String, preferred: [String] = Locale.preferredLanguages) -> String {
        if setting == "zh" || setting == "en" { return setting }
        for tag in preferred {
            let lower = tag.lowercased()
            if lower.hasPrefix("zh") { return "zh" }
            if lower.hasPrefix("en") { return "en" }
        }
        return "en"
    }

    static var english: Bool { resolved(setting) == "en" }

    /// For dates and numbers in the interface language.
    static var locale: Locale { Locale(identifier: english ? "en_US" : "zh_Hans_CN") }
}

/// The interface text for `text`, written in Chinese; `{name}` placeholders
/// take `arguments`. A `context` picks a word's other English sense: the
/// tab "连接" (`tab|连接`) is not the connection count "连接".
func L(_ text: String, context: String? = nil, _ arguments: [String: Any] = [:]) -> String {
    var result = text
    if Localization.english {
        result = context.flatMap { englishText["\($0)|\(text)"] } ?? englishText[text] ?? text
    }
    for (name, value) in arguments {
        result = result.replacingOccurrences(of: "{\(name)}", with: "\(value)")
    }
    return result
}
