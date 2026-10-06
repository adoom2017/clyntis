import SwiftUI
import UIKit

@main
struct ClyntisApp: App {
    @State private var model = AppModel()
    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .tint(.brand)
                .task { await model.load() }
        }
    }
}

extension Color {
    /// Apple system colours adapt to light/dark mode and Increase Contrast automatically.
    static let brand = Color(uiColor: .systemBlue)
    /// Reserved for the connected state, matching Settings' VPN indicator.
    static let connected = Color(uiColor: .systemGreen)
}
