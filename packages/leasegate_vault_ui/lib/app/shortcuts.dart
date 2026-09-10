import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

/// Focus the search field.
class SearchIntent extends Intent {
  const SearchIntent();
}

/// Create a new item in the current section.
class NewItemIntent extends Intent {
  const NewItemIntent();
}

/// Open settings.
class SettingsIntent extends Intent {
  const SettingsIntent();
}

/// Lock the vault.
class LockIntent extends Intent {
  const LockIntent();
}

/// Move the list selection.
class MoveSelectionIntent extends Intent {
  const MoveSelectionIntent(this.delta);

  final int delta;
}

/// The app-level accelerators.
///
/// macOS and Windows/Linux use their own modifier so the same intents work
/// everywhere; touch platforms simply never fire them.
Map<ShortcutActivator, Intent> appShortcuts({TargetPlatform? platform}) {
  final meta = (platform ?? defaultTargetPlatform) == TargetPlatform.macOS;
  SingleActivator accelerator(LogicalKeyboardKey key) =>
      SingleActivator(key, meta: meta, control: !meta);
  return {
    accelerator(LogicalKeyboardKey.keyF): const SearchIntent(),
    accelerator(LogicalKeyboardKey.keyN): const NewItemIntent(),
    accelerator(LogicalKeyboardKey.comma): const SettingsIntent(),
    accelerator(LogicalKeyboardKey.keyL): const LockIntent(),
  };
}
