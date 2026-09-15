import Foundation

/// Password generator shape (Dart `PasswordPattern`).
public enum PasswordPattern: String, Codable, CaseIterable, Equatable,
    Sendable
{
    case random, words, pin
}

/// Persisted generator preferences — port of `PasswordGeneratorSettings`.
/// Codable so the app can store it inside `~/.keylease/ui.json`.
public struct PasswordGeneratorSettings: Codable, Equatable, Sendable {
    public var pattern: PasswordPattern = .random
    public var length: Int = 24
    public var wordCount: Int = 5
    public var pinLength: Int = 6
    public var separator: String = "-"
    public var uppercase = true
    public var lowercase = true
    public var numbers = true
    public var symbols = true
    public var avoidAmbiguous = true
    public var capitalize = false
    public var wordNumber = true

    public init() {}

    public static let lengths = [16, 20, 24, 32, 40, 64]
    public static let wordCounts = [3, 4, 5, 6, 7, 8]
    public static let pinLengths = [4, 6, 8, 10, 12]
    public static let separators = ["-", " ", ".", "_"]

    /// `fromJson` — unknown or out-of-range values fall back to defaults.
    public init(json: JSONValue) {
        guard let object = json.objectValue else { return }
        switch object["pattern"]?.stringValue {
        case "words": pattern = .words
        case "pin": pattern = .pin
        default: pattern = .random
        }
        if let raw = object["length"]?.intValue,
            Self.lengths.contains(Int(raw))
        {
            length = Int(raw)
        }
        if let raw = object["word_count"]?.intValue,
            Self.wordCounts.contains(Int(raw))
        {
            wordCount = Int(raw)
        }
        if let raw = object["pin_length"]?.intValue,
            Self.pinLengths.contains(Int(raw))
        {
            pinLength = Int(raw)
        }
        if let raw = object["separator"]?.stringValue,
            Self.separators.contains(raw)
        {
            separator = raw
        }
        if let raw = object["uppercase"]?.boolValue { uppercase = raw }
        if let raw = object["lowercase"]?.boolValue { lowercase = raw }
        if let raw = object["numbers"]?.boolValue { numbers = raw }
        if let raw = object["symbols"]?.boolValue { symbols = raw }
        if let raw = object["avoid_ambiguous"]?.boolValue {
            avoidAmbiguous = raw
        }
        if let raw = object["capitalize"]?.boolValue { capitalize = raw }
        if let raw = object["word_number"]?.boolValue { wordNumber = raw }
    }

    /// `requestLength` — pins use `pinLength`, everything else `length`.
    public var requestLength: UInt {
        UInt(pattern == .pin ? pinLength : length)
    }

    /// `recipe` for `generate_password`.
    public var recipe: PasswordRecipe {
        switch pattern {
        case .random:
            return .random(
                length: UInt(length), uppercase: uppercase,
                lowercase: lowercase, numbers: numbers, symbols: symbols,
                avoidAmbiguous: avoidAmbiguous)
        case .words:
            return .words(
                count: UInt(wordCount), separator: separator,
                capitalize: capitalize, includeNumber: wordNumber)
        case .pin:
            return .pin(length: UInt(pinLength))
        }
    }

    /// `toJson` — the shape stored under `password_generator`.
    public var jsonObject: [String: JSONValue] {
        [
            "pattern": .string(pattern.rawValue),
            "length": .int(Int64(length)),
            "word_count": .int(Int64(wordCount)),
            "pin_length": .int(Int64(pinLength)),
            "separator": .string(separator),
            "uppercase": .bool(uppercase),
            "lowercase": .bool(lowercase),
            "numbers": .bool(numbers),
            "symbols": .bool(symbols),
            "avoid_ambiguous": .bool(avoidAmbiguous),
            "capitalize": .bool(capitalize),
            "word_number": .bool(wordNumber),
        ]
    }

    /// Entropy estimate for the strength label — the Dart pane's
    /// `_entropyBits`: `log2(pool^count)` where the pool counts the actual
    /// character classes the daemon recipe draws from (24/25/8/14, not the
    /// naive 26/26/10/32, because ambiguous glyphs are always skipped).
    public var estimatedEntropyBits: Int {
        switch pattern {
        case .random:
            let pool = Double(
                (uppercase ? 24 : 0) + (lowercase ? 25 : 0)
                    + (numbers ? 8 : 0) + (symbols ? 14 : 0))
            guard pool > 0 else { return 0 }
            return Int((Double(length) * log2(pool)).rounded())
        case .words:
            return wordCount * 12 + (wordNumber ? 7 : 0)
        case .pin:
            return Int((Double(pinLength) * log2(10)).rounded())
        }
    }

    /// `Weak` / `Fair` / `Strong` / `Very strong` bands from the Dart pane.
    public var strengthLabel: String {
        switch estimatedEntropyBits {
        case ..<40: return "Weak"
        case ..<60: return "Fair"
        case ..<80: return "Strong"
        default: return "Very strong"
        }
    }
}
