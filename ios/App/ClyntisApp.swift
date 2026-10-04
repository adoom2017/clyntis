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
    /// Brand green; lifted in dark mode so it keeps contrast on dark grouped backgrounds.
    static let brand = Color(UIColor { traits in
        traits.userInterfaceStyle == .dark
            ? UIColor(red: 0.27, green: 0.77, blue: 0.59, alpha: 1)
            : UIColor(red: 0.06, green: 0.47, blue: 0.35, alpha: 1)
    })
}
