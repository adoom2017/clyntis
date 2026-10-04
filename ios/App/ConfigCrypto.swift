import Foundation

/// Legacy AES-CFB/Base64 configuration encryption shared with the desktop app.
enum ConfigCrypto {
    static let decryptFailed = "解密失败，请检查密码和文件格式。"

    /// Encrypted files are a single Base64 blob; a YAML configuration always contains `key: value`.
    static func looksEncrypted(_ data: Data) -> Bool {
        let base64 = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".utf8)
        let text = data.filter { !($0 == 0x20 || (0x09...0x0d).contains($0)) }
        return text.count >= 16 && text.allSatisfy(base64.contains)
    }

    static func decrypt(_ source: Data, password: String) throws -> Data {
        do {
            return try call(source, password: password, limit: ProfileStore.maximumBytes, meta_decrypt_config_v1)
        } catch is CancellationError { throw CancellationError() }
        catch { throw ClientError.message(decryptFailed) }
    }

    static func encrypt(_ plaintext: Data, password: String) throws -> Data {
        guard !password.isEmpty else { throw ClientError.message("密码不能为空。") }
        return try call(plaintext, password: password, limit: 24 * 1024 * 1024, meta_encrypt_config_v1)
    }

    private typealias Operation = (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int,
                                   UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>?) -> Int32

    /// Size query first, then fill a buffer of exactly that size.
    private static func call(_ input: Data, password: String, limit: Int, _ operation: Operation) throws -> Data {
        let password = Data(password.utf8)
        return try input.withUnsafeBytes { input in
            try password.withUnsafeBytes { password in
                let source = input.bindMemory(to: UInt8.self).baseAddress
                let key = password.bindMemory(to: UInt8.self).baseAddress
                var length = 0
                let query = operation(source, input.count, key, password.count, nil, 0, &length)
                guard query == META_BUFFER_TOO_SMALL else {
                    try CoreSession.check(query)
                    throw ClientError.message("配置为空。")
                }
                guard length > 0, length <= limit else { throw ClientError.message("配置超过大小限制。") }
                var output = Data(count: length)
                let status = output.withUnsafeMutableBytes {
                    operation(source, input.count, key, password.count,
                              $0.bindMemory(to: UInt8.self).baseAddress, $0.count, &length)
                }
                try CoreSession.check(status)
                return output.prefix(length)
            }
        }
    }
}
