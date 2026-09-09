import 'dart:convert';

import '../../core/models/models.dart';

final _environmentKey = RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$');
final _sshAlias = RegExp(r'^[A-Za-z0-9._-]+$');
var _structuredIdSequence = 0;

String structuredId(String prefix, [int salt = 0]) =>
    '${prefix}_${DateTime.now().microsecondsSinceEpoch}_${salt}_${_structuredIdSequence++}';

Map<String, dynamic> structuredTextField({
  required String id,
  required String key,
  required String label,
  required String role,
  required String value,
  bool secret = false,
}) => {
  'id': id,
  'key': key,
  'label': label,
  'value': {'type': secret ? 'concealed' : 'text', 'value': value},
  'sensitivity': secret ? 'highly_sensitive' : 'private_metadata',
  'protected': secret,
  'semantic_role': role,
};

class EnvVariableDraft {
  EnvVariableDraft({
    required this.id,
    required this.key,
    required this.value,
    this.secret = true,
    this.existing = false,
    this.hasStoredValue = false,
    this.dirty = true,
  });

  final String id;
  String key;
  String value;
  bool secret;
  final bool existing;
  final bool hasStoredValue;
  bool dirty;

  Map<String, dynamic> toField() => structuredTextField(
    id: id,
    key: 'env.$key',
    label: key,
    role: 'environment_variable',
    value: value,
    secret: secret,
  );
}

class EnvParseIssue {
  const EnvParseIssue(this.line, this.message);

  final int line;
  final String message;
}

class EnvParseResult {
  const EnvParseResult({
    required this.variables,
    required this.issues,
    required this.ignoredComments,
    required this.ignoredBlankLines,
    required this.normalizedExports,
  });

  final List<EnvVariableDraft> variables;
  final List<EnvParseIssue> issues;
  final int ignoredComments;
  final int ignoredBlankLines;
  final int normalizedExports;

  bool get valid => issues.isEmpty;
}

EnvParseResult parseDotEnv(String source) {
  final normalized = source.replaceFirst('\ufeff', '').replaceAll('\r\n', '\n');
  final lines = normalized.split('\n');
  final variables = <EnvVariableDraft>[];
  final issues = <EnvParseIssue>[];
  final seen = <String>{};
  var comments = 0;
  var blanks = 0;
  var exports = 0;
  var index = 0;
  while (index < lines.length) {
    final lineNumber = index + 1;
    var line = lines[index];
    final trimmed = line.trim();
    if (trimmed.isEmpty) {
      blanks++;
      index++;
      continue;
    }
    if (trimmed.startsWith('#')) {
      comments++;
      index++;
      continue;
    }
    line = line.trimLeft();
    if (line.startsWith('export ')) {
      exports++;
      line = line.substring(7).trimLeft();
    }
    final equals = line.indexOf('=');
    if (equals < 1) {
      issues.add(EnvParseIssue(lineNumber, 'Expected KEY=value.'));
      index++;
      continue;
    }
    final key = line.substring(0, equals).trim();
    if (!_environmentKey.hasMatch(key)) {
      issues.add(EnvParseIssue(lineNumber, 'Invalid variable name "$key".'));
      index++;
      continue;
    }
    if (!seen.add(key)) {
      issues.add(EnvParseIssue(lineNumber, 'Duplicate variable "$key".'));
      index++;
      continue;
    }
    var raw = line.substring(equals + 1).trimLeft();
    String value;
    if (raw.startsWith("'") || raw.startsWith('"')) {
      final quote = raw[0];
      final buffer = StringBuffer();
      var closed = false;
      raw = raw.substring(1);
      while (true) {
        var cursor = 0;
        while (cursor < raw.length) {
          final char = raw[cursor];
          if (char == quote && (quote == "'" || !_isEscaped(raw, cursor))) {
            final trailing = raw.substring(cursor + 1).trim();
            if (trailing.isNotEmpty && !trailing.startsWith('#')) {
              issues.add(
                EnvParseIssue(
                  lineNumber,
                  'Unexpected text after quoted value.',
                ),
              );
            }
            closed = true;
            break;
          }
          if (quote == '"' && char == r'\' && cursor + 1 < raw.length) {
            final next = raw[++cursor];
            buffer.write(switch (next) {
              'n' => '\n',
              'r' => '\r',
              't' => '\t',
              '"' => '"',
              r'\' => r'\',
              r'$' => r'$',
              _ => next,
            });
          } else {
            buffer.write(char);
          }
          cursor++;
        }
        if (closed || index + 1 >= lines.length) break;
        buffer.write('\n');
        raw = lines[++index];
      }
      if (!closed) {
        issues.add(EnvParseIssue(lineNumber, 'Unclosed quoted value.'));
      }
      value = buffer.toString();
    } else {
      final comment = _unquotedComment(raw);
      if (comment >= 0) raw = raw.substring(0, comment);
      value = raw.trimRight();
    }
    variables.add(
      EnvVariableDraft(
        id: structuredId('field_env', variables.length),
        key: key,
        value: value,
      ),
    );
    index++;
  }
  return EnvParseResult(
    variables: variables,
    issues: issues,
    ignoredComments: comments,
    ignoredBlankLines: blanks,
    normalizedExports: exports,
  );
}

bool _isEscaped(String value, int index) {
  var slashes = 0;
  for (var cursor = index - 1; cursor >= 0 && value[cursor] == r'\'; cursor--) {
    slashes++;
  }
  return slashes.isOdd;
}

int _unquotedComment(String value) {
  for (var index = 1; index < value.length; index++) {
    if (value[index] == '#' && value[index - 1].trim().isEmpty) return index;
  }
  return -1;
}

String renderDotEnv(Iterable<MapEntry<String, String>> variables) {
  final output = StringBuffer();
  for (final variable in variables) {
    output
      ..write(variable.key)
      ..write('=')
      ..writeln(_renderEnvValue(variable.value));
  }
  return output.toString();
}

String _renderEnvValue(String value) {
  if (value.isEmpty) return '';
  if (RegExp(r'^[A-Za-z0-9_./:@%+,=-]+$').hasMatch(value)) return value;
  if (!value.contains("'") && !value.contains('\n') && !value.contains('\r')) {
    return "'$value'";
  }
  return '"${value.replaceAll(r'\', r'\\').replaceAll('"', r'\"').replaceAll(r'$', r'\$').replaceAll('\n', r'\n').replaceAll('\r', r'\r').replaceAll('\t', r'\t')}"';
}

class SshEndpointConfig {
  const SshEndpointConfig({
    required this.sectionId,
    required this.name,
    required this.alias,
    required this.host,
    required this.port,
    required this.username,
    required this.authMode,
    this.connectVia,
  });

  final String sectionId;
  final String name;
  final String alias;
  final String host;
  final int port;
  final String username;
  final String authMode;
  final String? connectVia;
}

class SshForwardConfig {
  const SshForwardConfig({
    required this.endpointId,
    required this.type,
    required this.bindAddress,
    required this.bindPort,
    required this.destinationHost,
    required this.destinationPort,
  });

  final String endpointId;
  final String type;
  final String bindAddress;
  final int bindPort;
  final String destinationHost;
  final int destinationPort;
}

String renderSshConfig({
  required List<SshEndpointConfig> endpoints,
  required List<SshForwardConfig> forwards,
  required Map<String, String> privateKeyPaths,
}) {
  final byId = {for (final endpoint in endpoints) endpoint.sectionId: endpoint};
  final output = StringBuffer();
  for (final endpoint in endpoints) {
    if (!_sshAlias.hasMatch(endpoint.alias)) {
      throw const FormatException('Invalid SSH alias.');
    }
    output
      ..writeln('Host ${endpoint.alias}')
      ..writeln('  HostName ${_sshToken(endpoint.host)}');
    if (endpoint.username.isNotEmpty) {
      output.writeln('  User ${_sshToken(endpoint.username)}');
    }
    output.writeln('  Port ${endpoint.port}');
    final path = privateKeyPaths[endpoint.sectionId];
    if (endpoint.authMode == 'private_key') {
      if (path == null || path.isEmpty) {
        throw FormatException(
          'Select a private key for ${endpoint.name} on this device.',
        );
      }
      output
        ..writeln('  IdentityFile ${_sshToken(path)}')
        ..writeln('  IdentitiesOnly yes');
    }
    final chain = <String>[];
    final seen = <String>{};
    var parent = endpoint.connectVia;
    while (parent != null && parent.isNotEmpty) {
      if (!seen.add(parent)) {
        throw const FormatException('SSH jump host cycle.');
      }
      final jump = byId[parent];
      if (jump == null) throw const FormatException('Missing SSH jump host.');
      chain.insert(0, jump.alias);
      parent = jump.connectVia;
    }
    if (chain.isNotEmpty) output.writeln('  ProxyJump ${chain.join(',')}');
    for (final forward in forwards.where(
      (item) => item.endpointId == endpoint.sectionId,
    )) {
      final bind = '${_sshToken(forward.bindAddress)}:${forward.bindPort}';
      if (forward.type == 'dynamic') {
        output.writeln('  DynamicForward $bind');
      } else {
        final destination =
            '${_sshToken(forward.destinationHost)}:${forward.destinationPort}';
        output.writeln(
          '  ${forward.type == 'remote' ? 'RemoteForward' : 'LocalForward'} $bind $destination',
        );
      }
    }
    output.writeln();
  }
  return output.toString();
}

String _sshToken(String value) {
  if (value.isEmpty || value.runes.any((character) => character < 32)) {
    throw const FormatException(
      'SSH values must not contain control characters.',
    );
  }
  if (RegExp(r'^[A-Za-z0-9_./:@%+,-]+$').hasMatch(value)) return value;
  return '"${value.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';
}

String? entryFieldText(EntryFieldView field) {
  if (field.protected) return null;
  final value = field.value;
  if (value is Map && value['value'] != null) return '${value['value']}';
  return field.displayValue;
}

Map<String, EntryFieldView> fieldsByRole(
  EntrySectionView section,
  EntryDetailView detail,
) => {
  for (final id in section.fieldIds)
    if (detail.fields.where((field) => field.id == id).firstOrNull
        case final field?)
      if (field.semanticRole case final role?) role: field,
};

String encodeStructuredSections(Iterable<EntrySectionView> sections) =>
    jsonEncode(
      sections.map((section) => section.toJson()).toList(growable: false),
    );
