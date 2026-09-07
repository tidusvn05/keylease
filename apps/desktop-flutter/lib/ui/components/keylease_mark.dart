import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

import '../tokens/keylease_tokens.dart';

/// The monogram tile used by entry rows and the entry detail header.
class KeyLeaseMark extends StatelessWidget {
  const KeyLeaseMark({required this.text, this.large = false, super.key});

  final String text;
  final bool large;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    final size = large ? tokens.largeMarkSize : tokens.markSize;
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: tokens.markSurface,
        borderRadius: BorderRadius.circular(large ? 13 : tokens.markRadius),
      ),
      child: Text(
        text,
        maxLines: 1,
        style: TextStyle(
          color: tokens.markForeground,
          fontWeight: FontWeight.w700,
          fontSize: large ? 22 : 15,
        ),
      ),
    );
  }
}

/// The KeyLease app icon shown in the sidebar header and state screens.
class KeyLeaseBrandMark extends StatelessWidget {
  const KeyLeaseBrandMark({this.size = 36, this.icon, super.key});

  final double size;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final tokens = KeyLeaseTokens.of(context);
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: tokens.accent,
        borderRadius: BorderRadius.circular(size / 3.4),
      ),
      child: Icon(
        icon ?? FLucideIcons.keyRound,
        color: tokens.onAccent,
        size: size * 0.55,
      ),
    );
  }
}
