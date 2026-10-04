import Foundation

enum RemoteConfigImporter {
    static func url(from address: String) throws -> URL {
        guard let url = URL(string: address.trimmingCharacters(in: .whitespacesAndNewlines),
                            encodingInvalidCharacters: false),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
              scheme == "https" || (scheme == "http" && isLoopback(host)) else {
            throw ClientError.message("请输入 HTTPS 配置链接。")
        }
        return url
    }

    // Configurations carry node credentials, so plain HTTP is only allowed when it never leaves the device.
    private static func isLoopback(_ host: String) -> Bool {
        let host = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return host == "localhost" || host == "::1" || host.hasPrefix("127.")
    }

    static func download(from url: URL, encrypted: Bool) async throws -> Data {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        return try await download(from: url, maximumBytes: encrypted ? 24 * 1024 * 1024 : ProfileStore.maximumBytes,
                                  session: session)
    }

    // Streaming bounds actual decoded bytes, even without Content-Length or with gzip.
    static func download(from url: URL, maximumBytes: Int, session: URLSession) async throws -> Data {
        _ = try Self.url(from: url.absoluteString)
        try Task.checkCancellation()
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        request.setValue("Clyntis/0.1 iOS", forHTTPHeaderField: "User-Agent")
        let (bytes, response) = try await session.bytes(for: request)
        let task = bytes.task
        defer { task.cancel() }
        return try await withTaskCancellationHandler {
            try await read(bytes, response: response, maximumBytes: maximumBytes)
        } onCancel: { task.cancel() }
    }

    private static func read(_ bytes: URLSession.AsyncBytes, response: URLResponse, maximumBytes: Int) async throws -> Data {
        try Task.checkCancellation()
        guard let response = response as? HTTPURLResponse,
              let finalURL = response.url else { throw ClientError.message("服务器未返回有效配置文件。") }
        _ = try Self.url(from: finalURL.absoluteString)
        guard (200..<300).contains(response.statusCode) else {
            throw ClientError.message("配置下载失败（HTTP \(response.statusCode)）。")
        }
        guard response.expectedContentLength <= Int64(maximumBytes) else {
            throw ClientError.message("远程配置文件超过大小限制。")
        }
        var data = Data(), chunk: [UInt8] = []
        chunk.reserveCapacity(64 * 1024)
        for try await byte in bytes {
            guard data.count + chunk.count < maximumBytes else {
                throw ClientError.message("远程配置文件超过大小限制。")
            }
            chunk.append(byte)
            if chunk.count == 64 * 1024 {
                try Task.checkCancellation()
                data.append(contentsOf: chunk)
                chunk.removeAll(keepingCapacity: true)
            }
        }
        try Task.checkCancellation()
        data.append(contentsOf: chunk)
        guard !data.isEmpty else { throw ClientError.message("远程配置文件为空。") }
        return data
    }

    static func store(_ source: Data, password: String, name: String, in store: ProfileStore) throws -> Profile {
        try Task.checkCancellation()
        let encrypted = !password.isEmpty
        let plaintext = encrypted ? try decrypt(source, password: password) : source
        try Task.checkCancellation()
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let profile = try store.add(name: name.isEmpty ? "远程配置" : name, configuration: plaintext) { bytes, directory in
                let core = try CoreSession(configuration: bytes, directory: directory)
                core.close()
                try Task.checkCancellation()
            }
            if Task.isCancelled {
                try store.remove(profile)
                throw CancellationError()
            }
            return profile
        } catch is CancellationError { throw CancellationError() }
        catch {
            if encrypted { throw ClientError.message("解密或配置校验失败，请检查密码和文件格式。") }
            throw error
        }
    }

    private static func decrypt(_ source: Data, password: String) throws -> Data {
        let password = Data(password.utf8)
        return try source.withUnsafeBytes { source in
            try password.withUnsafeBytes { password in
                var length = 0
                let result = meta_decrypt_config_v1(
                    source.bindMemory(to: UInt8.self).baseAddress, source.count,
                    password.bindMemory(to: UInt8.self).baseAddress, password.count, nil, 0, &length)
                guard result == META_BUFFER_TOO_SMALL, length > 0, length <= ProfileStore.maximumBytes else {
                    throw ClientError.message("解密或配置校验失败，请检查密码和文件格式。")
                }
                var plaintext = Data(count: length)
                let status = plaintext.withUnsafeMutableBytes {
                    meta_decrypt_config_v1(source.bindMemory(to: UInt8.self).baseAddress, source.count,
                        password.bindMemory(to: UInt8.self).baseAddress, password.count,
                        $0.bindMemory(to: UInt8.self).baseAddress, $0.count, &length)
                }
                guard status == META_OK else {
                    throw ClientError.message("解密或配置校验失败，请检查密码和文件格式。")
                }
                return plaintext.prefix(length)
            }
        }
    }
}
