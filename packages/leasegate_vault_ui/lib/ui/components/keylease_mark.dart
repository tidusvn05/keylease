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
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: const Color(0xFF071426),
        borderRadius: BorderRadius.circular(size / 3.4),
      ),
      child: icon == null
          ? CustomPaint(
              size: Size.square(size * 0.72),
              painter: const _LeasegateSymbolPainter(),
            )
          : Icon(icon, color: const Color(0xFFF5F8FC), size: size * 0.55),
    );
  }
}

class _LeasegateSymbolPainter extends CustomPainter {
  const _LeasegateSymbolPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final gate = Path()
      ..moveTo(size.width * 0.18, size.height * 0.84)
      ..lineTo(size.width * 0.18, size.height * 0.36)
      ..cubicTo(
        size.width * 0.18,
        size.height * 0.23,
        size.width * 0.29,
        size.height * 0.12,
        size.width * 0.42,
        size.height * 0.12,
      )
      ..lineTo(size.width * 0.70, size.height * 0.12)
      ..cubicTo(
        size.width * 0.78,
        size.height * 0.12,
        size.width * 0.84,
        size.height * 0.18,
        size.width * 0.84,
        size.height * 0.26,
      )
      ..lineTo(size.width * 0.84, size.height * 0.45)
      ..lineTo(size.width * 0.66, size.height * 0.45)
      ..lineTo(size.width * 0.66, size.height * 0.31)
      ..lineTo(size.width * 0.42, size.height * 0.31)
      ..cubicTo(
        size.width * 0.39,
        size.height * 0.31,
        size.width * 0.36,
        size.height * 0.34,
        size.width * 0.36,
        size.height * 0.37,
      )
      ..lineTo(size.width * 0.36, size.height * 0.84)
      ..close();
    canvas.drawPath(gate, Paint()..color = const Color(0xFF2F72FF));

    final access = Path()
      ..moveTo(size.width * 0.48, size.height * 0.40)
      ..lineTo(size.width * 0.72, size.height * 0.54)
      ..lineTo(size.width * 0.72, size.height * 0.76)
      ..lineTo(size.width * 0.48, size.height * 0.90)
      ..close();
    canvas.drawPath(access, Paint()..color = const Color(0xFF36E3A2));
  }

  @override
  bool shouldRepaint(covariant _LeasegateSymbolPainter oldDelegate) => false;
}
