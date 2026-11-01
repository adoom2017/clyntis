import XCTest
@testable import Clyntis

final class LocalizationTests: XCTestCase {
    private func placeholders(_ text: String) -> [String] {
        let pattern = try! NSRegularExpression(pattern: #"\{(\w+)\}"#)
        return pattern.matches(in: text, range: NSRange(text.startIndex..., in: text))
            .map { String(text[Range($0.range(at: 1), in: text)!]) }
            .sorted()
    }

    /// Every L("…") in the app, shared code and tunnel has English with the
    /// same placeholders, and no entry is stale. The simulator reads the
    /// sources next to this file.
    func testEveryInterfaceTextHasEnglish() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let call = try NSRegularExpression(pattern: #"\bL\("((?:[^"\\]|\\.)*)"(, context: "(\w+)")?"#)
        var keys = Set<String>()
        for folder in ["App", "Shared", "Tunnel"] {
            let directory = root.appendingPathComponent(folder)
            for name in try FileManager.default.contentsOfDirectory(atPath: directory.path) where name.hasSuffix(".swift") {
                guard name != "LocalizationEnglish.swift" else { continue }
                let source = try String(contentsOf: directory.appendingPathComponent(name), encoding: .utf8)
                for match in call.matches(in: source, range: NSRange(source.startIndex..., in: source)) {
                    let text = String(source[Range(match.range(at: 1), in: source)!])
                        .replacingOccurrences(of: #"\""#, with: "\"")
                    keys.insert(text)
                    if let context = Range(match.range(at: 3), in: source) {
                        keys.insert("\(source[context])|\(text)")
                    }
                }
            }
        }
        XCTAssertGreaterThan(keys.count, 300)
        XCTAssertEqual(keys.filter { englishText[$0] == nil }.sorted(), [])
        XCTAssertEqual(englishText.keys.filter { !keys.contains($0) }.sorted(), [])
        for (key, value) in englishText {
            XCTAssertEqual(placeholders(value), placeholders(key.components(separatedBy: "|").last!), key)
        }
    }

    func testFollowsTheSystemAndFallsBackToEnglish() {
        XCTAssertEqual(Localization.resolved("system", preferred: ["zh-Hans-CN", "en-US"]), "zh")
        XCTAssertEqual(Localization.resolved("system", preferred: ["en-GB"]), "en")
        XCTAssertEqual(Localization.resolved("system", preferred: ["ja-JP", "zh-Hant"]), "zh")
        XCTAssertEqual(Localization.resolved("system", preferred: ["ja-JP"]), "en")
        XCTAssertEqual(Localization.resolved("zh", preferred: ["en-US"]), "zh")
        XCTAssertEqual(Localization.resolved("en", preferred: ["zh-Hans"]), "en")
    }

    func testLooksUpTheChosenLanguageWithContextAndArguments() {
        let saved = Localization.setting
        defer { Localization.setting = saved }
        Localization.setting = "en"
        XCTAssertEqual(L("连接", context: "tab"), "Connection")
        XCTAssertEqual(L("连接"), "Connections")
        XCTAssertEqual(L("关闭全部 {count} 个连接？", ["count": 3]), "Close all 3 connections?")
        XCTAssertEqual(L("一段没有译文的文字"), "一段没有译文的文字")
        Localization.setting = "zh"
        XCTAssertEqual(L("连接", context: "tab"), "连接")
        XCTAssertEqual(L("关闭全部 {count} 个连接？", ["count": 3]), "关闭全部 3 个连接？")
    }
}
