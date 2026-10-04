import SwiftUI

@main
struct ClyntisApp: App {
    @State private var model = AppModel()
    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .tint(Color(red: 0.13, green: 0.52, blue: 0.40))
                .task { await model.load() }
        }
    }
}
