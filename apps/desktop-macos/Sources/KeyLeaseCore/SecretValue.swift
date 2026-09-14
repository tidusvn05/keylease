import Foundation

/// Transparent string wrapper whose textual form is redacted, mirroring
/// `SecretValue` in `keylease-core/src/domain.rs`. Pass secrets through the
/// client in this box so accidental logging cannot print them.
public struct SecretValue: Codable, Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible
{
    public let raw: String

    public init(_ raw: String) { self.raw = raw }

    public init(from decoder: Decoder) throws {
        raw = try decoder.singleValueContainer().decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(raw)
    }

    public var description: String { "SecretValue([REDACTED])" }
    public var debugDescription: String { description }
}
