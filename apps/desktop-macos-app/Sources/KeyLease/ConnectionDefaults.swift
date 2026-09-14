import Foundation

/// Where a desktop install keeps its managed socket and client token.
///
/// Port of `desktop_connection_defaults.dart`; none of these values is a
/// secret — the token itself stays in the mode-0600 file the daemon checks.
enum ConnectionDefaults {
    static var home: String {
        ProcessInfo.processInfo.environment["HOME"]
            ?? NSHomeDirectory()
    }

    static var socketPath: String {
        "\(home)/.keylease/run/keylease.sock"
    }

    static let agentId = "agent_desktop"

    static var tokenPath: String {
        "\(home)/.keylease/desktop.token"
    }
}
