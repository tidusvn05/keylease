import 'package:flutter/material.dart';

import 'spike_model.dart';

const spikeBlue = Color(0xff0b68d5);

class SpikeEntryList extends StatelessWidget {
  const SpikeEntryList({
    required this.model,
    required this.onSelect,
    super.key,
  });

  final SpikeVaultModel model;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) {
    final entries = model.visibleEntries;
    if (entries.isEmpty) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text('No items match this search.'),
        ),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(8, 4, 8, 12),
      itemCount: entries.length,
      itemBuilder: (context, index) {
        final entry = entries[index];
        final selected = model.selected?.id == entry.id;
        return Semantics(
          selected: selected,
          button: true,
          child: MouseRegion(
            key: ValueKey('entry-${entry.id}'),
            cursor: SystemMouseCursors.click,
            child: GestureDetector(
              behavior: HitTestBehavior.opaque,
              onTap: () => onSelect(entry.id),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 100),
                margin: const EdgeInsets.only(bottom: 2),
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                decoration: BoxDecoration(
                  color: selected
                      ? spikeBlue.withValues(alpha: 0.14)
                      : Colors.transparent,
                  borderRadius: BorderRadius.circular(7),
                  border: Border.all(
                    color: selected
                        ? spikeBlue.withValues(alpha: 0.24)
                        : Colors.transparent,
                  ),
                ),
                child: Row(
                  children: [
                    SpikeMark(entry: entry),
                    const SizedBox(width: 11),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            entry.title,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                              color: selected ? spikeBlue : null,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            entry.username,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                    if (entry.favorite)
                      const Icon(Icons.star_outline_rounded, size: 15),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}

class SpikeMark extends StatelessWidget {
  const SpikeMark({required this.entry, this.large = false, super.key});

  final SpikeEntry entry;
  final bool large;

  @override
  Widget build(BuildContext context) {
    final size = large ? 54.0 : 37.0;
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: entry.id == 'github'
            ? const Color(0xff252b36)
            : spikeBlue.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(large ? 13 : 9),
      ),
      child: Text(
        entry.mark,
        style: TextStyle(
          color: entry.id == 'github' ? Colors.white : spikeBlue,
          fontWeight: FontWeight.w700,
          fontSize: large ? 22 : 15,
        ),
      ),
    );
  }
}

class SpikeEntryDetail extends StatelessWidget {
  const SpikeEntryDetail({
    required this.model,
    required this.onReveal,
    required this.actionBuilder,
    super.key,
  });

  final SpikeVaultModel model;
  final VoidCallback onReveal;
  final Widget Function(String label, IconData icon, VoidCallback action)
      actionBuilder;

  @override
  Widget build(BuildContext context) {
    final entry = model.selected;
    if (entry == null) {
      return const Center(child: Text('Select an item to see its details.'));
    }
    return ListView(
      padding: const EdgeInsets.fromLTRB(38, 30, 38, 30),
      children: [
        Row(
          children: [
            SpikeMark(entry: entry, large: true),
            const SizedBox(width: 15),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    entry.title,
                    style: const TextStyle(
                      fontSize: 25,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 5),
                  Text(entry.website),
                ],
              ),
            ),
            actionBuilder('Edit', Icons.edit_outlined, () {}),
          ],
        ),
        const SizedBox(height: 31),
        const SpikeSectionLabel('Login details'),
        SpikeFieldGroup(
          children: [
            SpikeField(
              label: 'Username',
              value: entry.username,
              action:
                  actionBuilder('Copy username', Icons.copy_outlined, () {}),
            ),
            SpikeField(
              label: 'Password',
              value: model.revealed ? 'Demo-only!47-sample' : '••••••••••••',
              monospace: true,
              action: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  actionBuilder(
                    model.revealed ? 'Hide password' : 'Reveal password',
                    model.revealed
                        ? Icons.visibility_off_outlined
                        : Icons.visibility_outlined,
                    onReveal,
                  ),
                  actionBuilder('Copy password', Icons.copy_outlined, () {}),
                ],
              ),
            ),
            SpikeField(
              label: 'Website',
              value: 'https://${entry.website}',
              accent: true,
              action: actionBuilder('Copy website', Icons.copy_outlined, () {}),
            ),
          ],
        ),
        if (entry.hasTotp) ...[
          const SizedBox(height: 25),
          const SpikeSectionLabel('Two-factor authentication'),
          SpikeFieldGroup(
            children: [
              SpikeField(
                label: 'One-time password',
                value: 'Available on request',
                action: actionBuilder('Show code', Icons.timer_outlined, () {}),
              ),
            ],
          ),
        ],
        const SizedBox(height: 25),
        const SpikeSectionLabel('Notes'),
        Container(
          padding: const EdgeInsets.all(15),
          decoration: BoxDecoration(
            border: Border.all(color: Theme.of(context).dividerColor),
            borderRadius: BorderRadius.circular(8),
          ),
          child: const Text(
            'Primary account for engineering.\nRecovery codes are stored in the team’s offline backup.',
            style: TextStyle(height: 1.6),
          ),
        ),
      ],
    );
  }
}

class SpikeSectionLabel extends StatelessWidget {
  const SpikeSectionLabel(this.text, {super.key});
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 9),
        child: Text(
          text.toUpperCase(),
          style: Theme.of(context).textTheme.labelSmall?.copyWith(
                letterSpacing: 0.7,
                fontWeight: FontWeight.w600,
              ),
        ),
      );
}

class SpikeFieldGroup extends StatelessWidget {
  const SpikeFieldGroup({required this.children, super.key});
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Container(
        decoration: BoxDecoration(
          border: Border.all(color: Theme.of(context).dividerColor),
          borderRadius: BorderRadius.circular(9),
        ),
        clipBehavior: Clip.antiAlias,
        child: Column(
          children: [
            for (var index = 0; index < children.length; index++) ...[
              if (index > 0) const Divider(height: 1),
              children[index],
            ],
          ],
        ),
      );
}

class SpikeField extends StatelessWidget {
  const SpikeField({
    required this.label,
    required this.value,
    required this.action,
    this.monospace = false,
    this.accent = false,
    super.key,
  });

  final String label;
  final String value;
  final Widget action;
  final bool monospace;
  final bool accent;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 12),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label, style: Theme.of(context).textTheme.labelSmall),
                  const SizedBox(height: 5),
                  Text(
                    value,
                    style: TextStyle(
                      fontSize: 13,
                      fontFamily: monospace ? 'Menlo' : null,
                      letterSpacing:
                          monospace && value.startsWith('•') ? 1.8 : 0,
                      color: accent ? spikeBlue : null,
                    ),
                  ),
                ],
              ),
            ),
            action,
          ],
        ),
      );
}
