import Foundation

struct Profile: Codable, Identifiable, Equatable {
    let id: UUID
    let name: String
    let createdAt: Date
}

enum ClientError: LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self { case .message(let text): text }
    }
}

struct ProfileStore {
    let root: URL
    static let maximumBytes = 16 * 1024 * 1024

    init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        var url = root
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }

    static func shared() throws -> ProfileStore {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "ClyntisAppGroup") as? String,
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            #if targetEnvironment(simulator)
            return try ProfileStore(root: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("ClyntisProfiles", isDirectory: true))
            #else
            throw ClientError.message("无法访问共享配置，请检查 App Group 签名配置。")
            #endif
        }
        return try ProfileStore(root: container.appendingPathComponent("Profiles", isDirectory: true))
    }

    func directory(for id: UUID) -> URL {
        root.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    func profiles() throws -> [Profile] {
        try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
            .compactMap { url in
                guard UUID(uuidString: url.lastPathComponent) != nil else { return nil }
                let profile = try JSONDecoder().decode(Profile.self, from: Data(contentsOf: url.appendingPathComponent("profile.json")))
                guard profile.id.uuidString == url.lastPathComponent else {
                    throw ClientError.message("配置索引与目录不一致。")
                }
                return profile
            }
            .sorted { $0.createdAt > $1.createdAt }
    }

    func configuration(for id: UUID) throws -> Data {
        let url = directory(for: id).appendingPathComponent("config.yaml")
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size > 0, size <= Self.maximumBytes else {
            throw ClientError.message("配置为空或超过 16 MiB。")
        }
        return try Data(contentsOf: url)
    }

    func add(name: String, configuration: Data, validate: (Data, URL) throws -> Void) throws -> Profile {
        guard !configuration.isEmpty, configuration.count <= Self.maximumBytes else {
            throw ClientError.message("配置为空或超过 16 MiB。")
        }
        let profile = Profile(id: UUID(), name: name, createdAt: Date())
        let directory = directory(for: profile.id)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        do {
            try validate(configuration, directory)
            try configuration.write(to: directory.appendingPathComponent("config.yaml"),
                                    options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            try JSONEncoder().encode(profile).write(to: directory.appendingPathComponent("profile.json"),
                                                    options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
        return profile
    }

    func remove(_ profile: Profile) throws {
        try FileManager.default.removeItem(at: directory(for: profile.id))
    }
}
