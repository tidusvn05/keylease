import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

/// A small uppercase heading above a group of fields.
class SectionLabel extends StatelessWidget {
  const SectionLabel(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 9),
    child: Text(
      text.toUpperCase(),
      style: context.theme.typography.body.xs.copyWith(
        letterSpacing: 0.7,
        fontWeight: FontWeight.w600,
        color: context.theme.colors.mutedForeground,
      ),
    ),
  );
}

/// A bordered stack of rows that reads as one surface.
class FieldGroup extends StatelessWidget {
  const FieldGroup({required this.children, super.key});

  final List<Widget> children;

  @override
  Widget build(BuildContext context) => DecoratedBox(
    decoration: BoxDecoration(
      border: Border.all(color: context.theme.colors.border),
      borderRadius: BorderRadius.circular(9),
    ),
    child: ClipRRect(
      borderRadius: BorderRadius.circular(9),
      child: Column(
        children: [
          for (var index = 0; index < children.length; index++) ...[
            if (index > 0)
              ColoredBox(
                color: context.theme.colors.border,
                child: const SizedBox(height: 1, width: double.infinity),
              ),
            children[index],
          ],
        ],
      ),
    ),
  );
}
