enum PasswordPattern { random, words, pin }

class PasswordGeneratorSettings {
  const PasswordGeneratorSettings({
    this.pattern = PasswordPattern.random,
    this.length = 24,
    this.wordCount = 5,
    this.pinLength = 6,
    this.separator = '-',
    this.uppercase = true,
    this.lowercase = true,
    this.numbers = true,
    this.symbols = true,
    this.avoidAmbiguous = true,
    this.capitalize = false,
    this.wordNumber = true,
  });

  factory PasswordGeneratorSettings.fromJson(Object? value) {
    if (value is! Map) return const PasswordGeneratorSettings();
    final json = Map<String, dynamic>.from(value);
    const lengths = {16, 20, 24, 32, 40, 64};
    const wordCounts = {3, 4, 5, 6, 7, 8};
    const pinLengths = {4, 6, 8, 10, 12};
    const separators = {'-', ' ', '.', '_'};
    final rawLength = json['length'] is num
        ? (json['length'] as num).toInt()
        : null;
    final rawWordCount = json['word_count'] is num
        ? (json['word_count'] as num).toInt()
        : null;
    final rawPinLength = json['pin_length'] is num
        ? (json['pin_length'] as num).toInt()
        : null;
    final rawSeparator = json['separator'] as String?;
    return PasswordGeneratorSettings(
      pattern: switch (json['pattern']) {
        'words' => PasswordPattern.words,
        'pin' => PasswordPattern.pin,
        _ => PasswordPattern.random,
      },
      length: lengths.contains(rawLength) ? rawLength! : 24,
      wordCount: wordCounts.contains(rawWordCount) ? rawWordCount! : 5,
      pinLength: pinLengths.contains(rawPinLength) ? rawPinLength! : 6,
      separator: separators.contains(rawSeparator) ? rawSeparator! : '-',
      uppercase: json['uppercase'] != false,
      lowercase: json['lowercase'] != false,
      numbers: json['numbers'] != false,
      symbols: json['symbols'] != false,
      avoidAmbiguous: json['avoid_ambiguous'] != false,
      capitalize: json['capitalize'] == true,
      wordNumber: json['word_number'] != false,
    );
  }

  final PasswordPattern pattern;
  final int length;
  final int wordCount;
  final int pinLength;
  final String separator;
  final bool uppercase;
  final bool lowercase;
  final bool numbers;
  final bool symbols;
  final bool avoidAmbiguous;
  final bool capitalize;
  final bool wordNumber;

  PasswordGeneratorSettings copyWith({
    PasswordPattern? pattern,
    int? length,
    int? wordCount,
    int? pinLength,
    String? separator,
    bool? uppercase,
    bool? lowercase,
    bool? numbers,
    bool? symbols,
    bool? avoidAmbiguous,
    bool? capitalize,
    bool? wordNumber,
  }) => PasswordGeneratorSettings(
    pattern: pattern ?? this.pattern,
    length: length ?? this.length,
    wordCount: wordCount ?? this.wordCount,
    pinLength: pinLength ?? this.pinLength,
    separator: separator ?? this.separator,
    uppercase: uppercase ?? this.uppercase,
    lowercase: lowercase ?? this.lowercase,
    numbers: numbers ?? this.numbers,
    symbols: symbols ?? this.symbols,
    avoidAmbiguous: avoidAmbiguous ?? this.avoidAmbiguous,
    capitalize: capitalize ?? this.capitalize,
    wordNumber: wordNumber ?? this.wordNumber,
  );

  int get requestLength => pattern == PasswordPattern.pin ? pinLength : length;

  Map<String, dynamic> get recipe => switch (pattern) {
    PasswordPattern.random => {
      'type': 'random',
      'length': length,
      'uppercase': uppercase,
      'lowercase': lowercase,
      'numbers': numbers,
      'symbols': symbols,
      'avoid_ambiguous': avoidAmbiguous,
    },
    PasswordPattern.words => {
      'type': 'words',
      'count': wordCount,
      'separator': separator,
      'capitalize': capitalize,
      'include_number': wordNumber,
    },
    PasswordPattern.pin => {'type': 'pin', 'length': pinLength},
  };

  Map<String, dynamic> toJson() => {
    'pattern': pattern.name,
    'length': length,
    'word_count': wordCount,
    'pin_length': pinLength,
    'separator': separator,
    'uppercase': uppercase,
    'lowercase': lowercase,
    'numbers': numbers,
    'symbols': symbols,
    'avoid_ambiguous': avoidAmbiguous,
    'capitalize': capitalize,
    'word_number': wordNumber,
  };
}
