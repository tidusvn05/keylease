import 'package:forui/forui.dart';
import 'package:material_ui/material_ui.dart';

class SearchSelectOption<T> {
  const SearchSelectOption({
    required this.value,
    required this.label,
    this.searchTerms = const [],
    this.section,
    this.subtitle,
  });

  final T value;
  final String label;
  final List<String> searchTerms;
  final String? section;
  final String? subtitle;

  bool matches(String query) {
    final needle = query.trim().toLowerCase();
    if (needle.isEmpty) return true;
    return [
      label,
      section ?? '',
      subtitle ?? '',
      ...searchTerms,
    ].join(' ').toLowerCase().contains(needle);
  }
}

/// A data-backed searchable select that keeps identity separate from labels.
/// This is important for groups, where two leaf nodes may share the same name.
class SearchableSelect<T> extends StatelessWidget {
  const SearchableSelect({
    required this.options,
    required this.value,
    required this.onChange,
    this.label,
    this.hint,
    this.forceErrorText,
    this.clearable = false,
    super.key,
  });

  final List<SearchSelectOption<T>> options;
  final T? value;
  final ValueChanged<T?> onChange;
  final Widget? label;
  final String? hint;
  final String? forceErrorText;
  final bool clearable;

  String _format(T selected) =>
      options
          .where((option) => option.value == selected)
          .map((option) => option.label)
          .firstOrNull ??
      '$selected';

  @override
  Widget build(BuildContext context) => FSelect<T>.searchBuilder(
    format: _format,
    filter: (query) => options
        .where((option) => option.matches(query))
        .map((option) => option.value),
    contentBuilder: (context, _, values) {
      final visible = values.toSet();
      final filtered = options
          .where((option) => visible.contains(option.value))
          .toList(growable: false);
      final sections = <String?>[];
      for (final option in filtered) {
        if (!sections.contains(option.section)) sections.add(option.section);
      }
      return [
        for (final section in sections)
          if (section == null)
            for (final option in filtered.where((item) => item.section == null))
              FSelectItem<T>(
                title: Text(option.label),
                subtitle: option.subtitle == null
                    ? null
                    : Text(option.subtitle!),
                value: option.value,
              )
          else
            FSelectSection<T>.rich(
              label: Text(section),
              children: [
                for (final option in filtered.where(
                  (item) => item.section == section,
                ))
                  FSelectItem<T>(
                    title: Text(option.label),
                    subtitle: option.subtitle == null
                        ? null
                        : Text(option.subtitle!),
                    value: option.value,
                  ),
              ],
            ),
      ];
    },
    label: label,
    hint: hint,
    forceErrorText: forceErrorText,
    clearable: clearable,
    control: FSelectControl<T>.lifted(value: value, onChange: onChange),
  );
}
