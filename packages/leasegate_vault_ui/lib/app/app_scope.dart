import 'package:material_ui/material_ui.dart';

import '../core/state/app_controller.dart';

/// Makes the session controller available to every feature without a DI
/// framework. Feature widgets listen to the controllers they actually use.
class AppScope extends InheritedNotifier<AppController> {
  const AppScope({
    required AppController controller,
    required super.child,
    super.key,
  }) : super(notifier: controller);

  static AppController of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<AppScope>();
    assert(scope != null, 'No AppScope found in context');
    return scope!.notifier!;
  }

  /// Reads the controller without subscribing to its notifications.
  static AppController read(BuildContext context) {
    final scope = context.getInheritedWidgetOfExactType<AppScope>();
    assert(scope != null, 'No AppScope found in context');
    return scope!.notifier!;
  }
}

/// Rebuilds [builder] whenever [listenable] notifies.
class Observe<T extends Listenable> extends StatelessWidget {
  const Observe({required this.listenable, required this.builder, super.key});

  final T listenable;
  final Widget Function(BuildContext context, T value) builder;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: listenable,
    builder: (context, _) => builder(context, listenable),
  );
}
