import 'package:material_ui/material_ui.dart';

/// A single-controller scroll surface whose scrollbar stays on the physical
/// edge while content padding remains inside the viewport.
class KeyLeaseScrollArea extends StatefulWidget {
  const KeyLeaseScrollArea({required this.children, this.padding, super.key})
    : itemBuilder = null,
      itemCount = null;

  const KeyLeaseScrollArea.builder({
    required this.itemBuilder,
    required this.itemCount,
    this.padding,
    super.key,
  }) : children = null;

  final List<Widget>? children;
  final IndexedWidgetBuilder? itemBuilder;
  final int? itemCount;
  final EdgeInsetsGeometry? padding;

  @override
  State<KeyLeaseScrollArea> createState() => _KeyLeaseScrollAreaState();
}

class _KeyLeaseScrollAreaState extends State<KeyLeaseScrollArea> {
  final _controller = ScrollController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final list = widget.itemBuilder == null
        ? ListView(
            controller: _controller,
            padding: widget.padding,
            children: widget.children!,
          )
        : ListView.builder(
            controller: _controller,
            padding: widget.padding,
            itemCount: widget.itemCount,
            itemBuilder: widget.itemBuilder!,
          );
    return ScrollConfiguration(
      behavior: ScrollConfiguration.of(context).copyWith(scrollbars: false),
      child: Scrollbar(
        controller: _controller,
        thumbVisibility: true,
        interactive: true,
        child: list,
      ),
    );
  }
}
