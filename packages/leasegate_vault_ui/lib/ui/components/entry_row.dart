import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/models/models.dart';
import '../tokens/keylease_tokens.dart';
import 'keylease_mark.dart';

/// One vault entry in the list.
///
/// Favorites are visible without opening an item.
class EntryRow extends StatelessWidget {
  const EntryRow({
    required this.entry,
    required this.selected,
    required this.onSelect,
    super.key,
  });

  final EntrySummary entry;
  final bool selected;
  final VoidCallback onSelect;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final subtitle = entry.subtitle;
    return Padding(
      padding: EdgeInsets.symmetric(horizontal: tokens.gutterSmall),
      child: FItem(
        key: ValueKey('entry-${entry.id}'),
        selected: selected,
        // Single press only: adding a double-tap handler would make every
        // click wait for the double-tap timeout before it selects.
        onPress: onSelect,
        semanticsLabel: subtitle.isEmpty
            ? entry.title
            : '${entry.title}, $subtitle',
        prefix: KeyLeaseMark(text: entry.monogram),
        title: Text(entry.title, maxLines: 1, overflow: TextOverflow.ellipsis),
        subtitle: subtitle.isEmpty
            ? null
            : Text(subtitle, maxLines: 1, overflow: TextOverflow.ellipsis),
        suffix: entry.favorite ? const Icon(FLucideIcons.star, size: 15) : null,
      ),
    );
  }
}
