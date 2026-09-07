import 'package:flutter/foundation.dart';
import 'package:material_ui/material_ui.dart';
import 'package:forui/forui.dart';

import 'spike_model.dart';
import 'spike_shared_widgets.dart';

void main() => runApp(const ForuiSpikeApp());

class ForuiSpikeApp extends StatelessWidget {
  const ForuiSpikeApp({super.key});

  @override
  Widget build(BuildContext context) {
    final platform = switch (defaultTargetPlatform) {
      TargetPlatform.iOS => FPlatformVariant.iOS,
      TargetPlatform.android => FPlatformVariant.android,
      TargetPlatform.macOS => FPlatformVariant.macOS,
      TargetPlatform.windows => FPlatformVariant.windows,
      TargetPlatform.linux => FPlatformVariant.linux,
      TargetPlatform.fuchsia => FPlatformVariant.android,
    };
    final theme = platform.desktop
        ? FTheme.neutral.light.desktop
        : FTheme.neutral.light.touch;
    return MaterialApp(
      title: 'KeyLease — Forui spike',
      debugShowCheckedModeBanner: false,
      localizationsDelegates: FLocalizations.localizationsDelegates,
      supportedLocales: FLocalizations.supportedLocales,
      theme: theme.toApproximateMaterialTheme().copyWith(
        dividerColor: const Color(0xffe1e5eb),
      ),
      builder: (context, child) => FTheme(
        data: theme,
        platform: platform,
        child: FToaster(child: FTooltipGroup(child: child!)),
      ),
      home: const ForuiVaultSpike(),
    );
  }
}

class ForuiVaultSpike extends StatefulWidget {
  const ForuiVaultSpike({super.key});

  @override
  State<ForuiVaultSpike> createState() => _ForuiVaultSpikeState();
}

class _ForuiVaultSpikeState extends State<ForuiVaultSpike> {
  final model = SpikeVaultModel();
  final search = TextEditingController();

  @override
  void initState() {
    super.initState();
    model.addListener(_redraw);
  }

  @override
  void dispose() {
    model.removeListener(_redraw);
    model.dispose();
    search.dispose();
    super.dispose();
  }

  void _redraw() => setState(() {});

  void selectGroup(String group) {
    search.clear();
    model.setGroup(group);
  }

  @override
  Widget build(BuildContext context) => FScaffold(
    childPad: false,
    sidebar: SizedBox(
      width: 224,
      child: FSidebar(
        header: const Padding(
          padding: EdgeInsets.fromLTRB(6, 6, 6, 15),
          child: Row(
            children: [
              _ForuiKeyLeaseMark(),
              SizedBox(width: 10),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'KeyLease',
                    style: TextStyle(fontWeight: FontWeight.w600),
                  ),
                  Text('Personal vault', style: TextStyle(fontSize: 11)),
                ],
              ),
            ],
          ),
        ),
        footer: const Padding(
          padding: EdgeInsets.all(7),
          child: Row(
            children: [
              Icon(FLucideIcons.circleCheck, size: 14),
              SizedBox(width: 7),
              Expanded(
                child: Text(
                  'Connected · Vault unlocked',
                  style: TextStyle(fontSize: 11),
                ),
              ),
            ],
          ),
        ),
        children: [
          FSidebarGroup(
            children: [
              _item('All items', FLucideIcons.layoutGrid, '6'),
              _item('Favorites', FLucideIcons.star, '3'),
            ],
          ),
          FSidebarGroup(
            label: const Text('Groups'),
            children: [
              _item('Work', FLucideIcons.folder),
              _item('Personal', FLucideIcons.folder),
              _item('Infrastructure', FLucideIcons.folder),
            ],
          ),
          const FSidebarGroup(
            label: Text('Workspace'),
            children: [
              FSidebarItem(
                icon: Icon(FLucideIcons.link),
                label: Text('Connections'),
              ),
              FSidebarItem(
                icon: Icon(FLucideIcons.shieldCheck),
                label: Text('Approvals · 2'),
              ),
              FSidebarItem(
                icon: Icon(FLucideIcons.clock),
                label: Text('Activity'),
              ),
            ],
          ),
        ],
      ),
    ),
    header: FHeader(
      title: Text(model.group),
      suffixes: [
        FHeaderAction(
          semanticsLabel: 'Lock vault',
          icon: const Icon(FLucideIcons.lock),
          onPress: () {},
        ),
        FButton(
          onPress: () {},
          prefix: const Icon(FLucideIcons.plus),
          child: const Text('New item'),
        ),
      ],
    ),
    child: LayoutBuilder(
      builder: (context, constraints) {
        final showDetail = constraints.maxWidth >= 660;
        return Row(
          children: [
            SizedBox(
              width: showDetail ? 306 : constraints.maxWidth,
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(15, 17, 15, 9),
                    child: FTextField(
                      key: const ValueKey('forui-search'),
                      control: FTextFieldControl.managed(
                        controller: search,
                        onChange: (value) => model.setQuery(value.text),
                      ),
                      hint: 'Search your vault',
                      prefixBuilder: (context, style, variants) =>
                          const Padding(
                            padding: EdgeInsets.only(left: 11, right: 6),
                            child: Icon(FLucideIcons.search, size: 17),
                          ),
                      clearable: (value) => value.text.isNotEmpty,
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                    child: Row(
                      children: [
                        Text(
                          '${model.visibleEntries.length} items',
                          style: const TextStyle(fontSize: 11),
                        ),
                        const Spacer(),
                        const Text(
                          'Recently used',
                          style: TextStyle(fontSize: 11),
                        ),
                      ],
                    ),
                  ),
                  Expanded(
                    child: SpikeEntryList(model: model, onSelect: model.select),
                  ),
                ],
              ),
            ),
            if (showDetail) ...[
              const VerticalDivider(width: 1),
              Expanded(
                child: SpikeEntryDetail(
                  model: model,
                  onReveal: model.toggleReveal,
                  actionBuilder: (label, icon, action) => KeyedSubtree(
                    key: ValueKey('action-$label'),
                    child: FTooltip(
                      tipBuilder: (context, controller) => Text(label),
                      child: FButton.icon(
                        onPress: action,
                        child: Icon(icon, semanticLabel: label, size: 17),
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ],
        );
      },
    ),
  );

  Widget _item(String label, IconData icon, [String? count]) => FSidebarItem(
    icon: Icon(icon),
    label: Row(
      children: [
        Expanded(child: Text(label)),
        if (count != null) Text(count, style: const TextStyle(fontSize: 11)),
      ],
    ),
    selected: model.group == label,
    onPress: () => selectGroup(label),
  );
}

class _ForuiKeyLeaseMark extends StatelessWidget {
  const _ForuiKeyLeaseMark();

  @override
  Widget build(BuildContext context) => Container(
    width: 36,
    height: 36,
    alignment: Alignment.center,
    decoration: BoxDecoration(
      color: spikeBlue,
      borderRadius: BorderRadius.circular(10),
    ),
    child: const Icon(FLucideIcons.keyRound, color: Colors.white, size: 20),
  );
}
