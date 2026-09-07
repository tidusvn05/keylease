import 'package:flutter/foundation.dart';

@immutable
class SpikeEntry {
  const SpikeEntry({
    required this.id,
    required this.title,
    required this.username,
    required this.website,
    required this.group,
    required this.mark,
    this.favorite = false,
    this.hasTotp = false,
  });

  final String id;
  final String title;
  final String username;
  final String website;
  final String group;
  final String mark;
  final bool favorite;
  final bool hasTotp;
}

class SpikeVaultModel extends ChangeNotifier {
  static const entries = <SpikeEntry>[
    SpikeEntry(
      id: 'github',
      title: 'GitHub',
      username: 'alex@northstar.example',
      website: 'github.com',
      group: 'Work',
      mark: 'GH',
      favorite: true,
      hasTotp: true,
    ),
    SpikeEntry(
      id: 'google',
      title: 'Google Workspace',
      username: 'alex@northstar.example',
      website: 'workspace.google.com',
      group: 'Work',
      mark: 'G',
      favorite: true,
      hasTotp: true,
    ),
    SpikeEntry(
      id: 'linear',
      title: 'Linear',
      username: 'alex@northstar.example',
      website: 'linear.app',
      group: 'Work',
      mark: 'L',
    ),
    SpikeEntry(
      id: 'notion',
      title: 'Notion',
      username: 'alex@northstar.example',
      website: 'notion.so',
      group: 'Work',
      mark: 'N',
    ),
    SpikeEntry(
      id: 'aws',
      title: 'AWS Console',
      username: 'alex.admin',
      website: 'aws.amazon.com',
      group: 'Infrastructure',
      mark: 'a',
      hasTotp: true,
    ),
    SpikeEntry(
      id: 'apple',
      title: 'Apple Account',
      username: 'alex@personal.example',
      website: 'account.apple.com',
      group: 'Personal',
      mark: 'A',
      favorite: true,
    ),
  ];

  String query = '';
  String group = 'All items';
  String selectedId = entries.first.id;
  bool revealed = false;

  List<SpikeEntry> get visibleEntries {
    final normalized = query.trim().toLowerCase();
    return entries.where((entry) {
      final inGroup = group == 'All items' ||
          (group == 'Favorites' ? entry.favorite : entry.group == group);
      final searchable =
          '${entry.title} ${entry.username} ${entry.website}'.toLowerCase();
      return inGroup && searchable.contains(normalized);
    }).toList(growable: false);
  }

  SpikeEntry? get selected {
    final visible = visibleEntries;
    if (visible.isEmpty) return null;
    return visible.firstWhere(
      (entry) => entry.id == selectedId,
      orElse: () => visible.first,
    );
  }

  void setQuery(String value) {
    query = value;
    _normalizeSelection();
    notifyListeners();
  }

  void setGroup(String value) {
    group = value;
    query = '';
    revealed = false;
    _normalizeSelection();
    notifyListeners();
  }

  void select(String id) {
    selectedId = id;
    revealed = false;
    notifyListeners();
  }

  void toggleReveal() {
    revealed = !revealed;
    notifyListeners();
  }

  void _normalizeSelection() {
    final visible = visibleEntries;
    if (visible.isNotEmpty && !visible.any((entry) => entry.id == selectedId)) {
      selectedId = visible.first.id;
    }
  }
}
