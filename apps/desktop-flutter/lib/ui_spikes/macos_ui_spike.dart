import 'package:flutter/cupertino.dart';
import 'package:macos_ui/macos_ui.dart';

import 'spike_model.dart';
import 'spike_shared_widgets.dart';

void main() => runApp(const MacosUiSpikeApp());

class MacosUiSpikeApp extends StatelessWidget {
  const MacosUiSpikeApp({super.key});

  @override
  Widget build(BuildContext context) => const MacosApp(
        title: 'KeyLease — macos_ui spike',
        debugShowCheckedModeBanner: false,
        home: MacosUiVaultSpike(),
      );
}

class MacosUiVaultSpike extends StatefulWidget {
  const MacosUiVaultSpike({super.key});

  @override
  State<MacosUiVaultSpike> createState() => _MacosUiVaultSpikeState();
}

class _MacosUiVaultSpikeState extends State<MacosUiVaultSpike> {
  final model = SpikeVaultModel();
  final search = TextEditingController();
  int sidebarIndex = 0;

  static const destinations = <String>[
    'All items',
    'Favorites',
    'Work',
    'Personal',
    'Infrastructure',
    'Connections',
    'Approvals',
    'Activity',
  ];

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

  void selectDestination(int index) {
    if (index > 4) return;
    setState(() => sidebarIndex = index);
    search.clear();
    model.setGroup(destinations[index]);
  }

  @override
  Widget build(BuildContext context) => MacosWindow(
        sidebar: Sidebar(
          minWidth: 190,
          startWidth: 214,
          maxWidth: 280,
          builder: (context, scrollController) => Column(
            children: [
              const Padding(
                padding: EdgeInsets.fromLTRB(14, 12, 14, 18),
                child: Row(
                  children: [
                    _KeyLeaseMark(),
                    SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'KeyLease',
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(fontWeight: FontWeight.w600),
                          ),
                          Text(
                            'Personal vault',
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(fontSize: 11),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: SidebarItems(
                  currentIndex: sidebarIndex,
                  onChanged: selectDestination,
                  scrollController: scrollController,
                  itemSize: SidebarItemSize.large,
                  items: const [
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.square_grid_2x2),
                      label: Text('All items'),
                      trailing: Text('6'),
                    ),
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.star),
                      label: Text('Favorites'),
                      trailing: Text('3'),
                    ),
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.folder),
                      label: Text('Work'),
                    ),
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.folder),
                      label: Text('Personal'),
                    ),
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.folder),
                      label: Text('Infrastructure'),
                    ),
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.link),
                      label: Text('Connections'),
                    ),
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.shield),
                      label: Text('Approvals'),
                      trailing: Text('2'),
                    ),
                    SidebarItem(
                      leading: MacosIcon(CupertinoIcons.clock),
                      label: Text('Activity'),
                    ),
                  ],
                ),
              ),
              const Padding(
                padding: EdgeInsets.all(14),
                child: Row(
                  children: [
                    Icon(CupertinoIcons.check_mark_circled, size: 14),
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
            ],
          ),
        ),
        child: MacosScaffold(
          toolBar: ToolBar(
            title: Text(model.group),
            titleWidth: 240,
            leading: Builder(
              builder: (context) => MacosIconButton(
                icon: const MacosIcon(CupertinoIcons.sidebar_left),
                onPressed: () => MacosWindowScope.of(context).toggleSidebar(),
              ),
            ),
            actions: [
              ToolBarIconButton(
                label: 'Lock',
                icon: const MacosIcon(CupertinoIcons.lock),
                showLabel: false,
                tooltipMessage: 'Lock vault',
                onPressed: () {},
              ),
              CustomToolbarItem(
                inToolbarBuilder: (context) => PushButton(
                  controlSize: ControlSize.regular,
                  color: MacosTheme.of(context).primaryColor,
                  onPressed: () {},
                  child: const Text('New item'),
                ),
              ),
            ],
          ),
          children: [
            ResizablePane.noScrollBar(
              minSize: 235,
              startSize: 306,
              maxSize: 400,
              windowBreakpoint: 720,
              resizableSide: ResizableSide.right,
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(15, 17, 15, 9),
                    child: MacosSearchField(
                      key: const ValueKey('macos-search'),
                      controller: search,
                      placeholder: 'Search your vault',
                      onChanged: model.setQuery,
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
                    child: SpikeEntryList(
                      model: model,
                      onSelect: model.select,
                    ),
                  ),
                ],
              ),
            ),
            ContentArea(
              builder: (context, scrollController) => SpikeEntryDetail(
                model: model,
                onReveal: model.toggleReveal,
                actionBuilder: (label, icon, action) => KeyedSubtree(
                  key: ValueKey('action-$label'),
                  child: MacosTooltip(
                    message: label,
                    child: MacosIconButton(
                      semanticLabel: label,
                      icon: Icon(icon, size: 17),
                      onPressed: action,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      );
}

class _KeyLeaseMark extends StatelessWidget {
  const _KeyLeaseMark();

  @override
  Widget build(BuildContext context) => Container(
        width: 36,
        height: 36,
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: MacosTheme.of(context).primaryColor,
          borderRadius: BorderRadius.circular(10),
        ),
        child: const Icon(
          CupertinoIcons.lock_shield,
          color: CupertinoColors.white,
        ),
      );
}
