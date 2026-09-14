import Foundation

/// Password recipe for `generate_password`, mirroring `PasswordRecipe` in
/// `crates/keylease-service/src/lib.rs`. Not part of `keylease contracts`
/// output, so this type is maintained by hand — keep it in sync.
public enum PasswordRecipe: Encodable, Equatable, Sendable {
    case random(
        length: UInt,
        uppercase: Bool = true,
        lowercase: Bool = true,
        numbers: Bool = true,
        symbols: Bool = true,
        avoidAmbiguous: Bool = true
    )
    case words(
        count: UInt,
        separator: String,
        capitalize: Bool = false,
        includeNumber: Bool = true
    )
    case pin(length: UInt)

    private enum CodingKeys: String, CodingKey {
        case type
        case length, uppercase, lowercase, numbers, symbols
        case avoidAmbiguous = "avoid_ambiguous"
        case count, separator, capitalize
        case includeNumber = "include_number"
    }

    private enum Kind: String, Encodable {
        case random, words, pin
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .random(
            let length, let uppercase, let lowercase, let numbers,
            let symbols, let avoidAmbiguous
        ):
            try container.encode(Kind.random, forKey: .type)
            try container.encode(length, forKey: .length)
            try container.encode(uppercase, forKey: .uppercase)
            try container.encode(lowercase, forKey: .lowercase)
            try container.encode(numbers, forKey: .numbers)
            try container.encode(symbols, forKey: .symbols)
            try container.encode(avoidAmbiguous, forKey: .avoidAmbiguous)
        case .words(let count, let separator, let capitalize, let includeNumber):
            try container.encode(Kind.words, forKey: .type)
            try container.encode(count, forKey: .count)
            try container.encode(separator, forKey: .separator)
            try container.encode(capitalize, forKey: .capitalize)
            try container.encode(includeNumber, forKey: .includeNumber)
        case .pin(let length):
            try container.encode(Kind.pin, forKey: .type)
            try container.encode(length, forKey: .length)
        }
    }
}
