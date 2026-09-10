enum EntryCreationMode { manual, agentDriven }

class AgentCreationRecipe {
  const AgentCreationRecipe({
    required this.id,
    required this.title,
    required this.description,
    required this.defaultKind,
    this.defaultSourcePath,
  });

  final String id;
  final String title;
  final String description;
  final String defaultKind;
  final String? defaultSourcePath;
}

const agentCreationRecipes = <AgentCreationRecipe>[
  AgentCreationRecipe(
    id: 'describe',
    title: 'Describe what to save',
    description:
        'Tell the agent what you need and let it ask for missing fields.',
    defaultKind: 'core.login',
  ),
  AgentCreationRecipe(
    id: 'project',
    title: 'Inspect current project',
    description: 'Build one item from the project currently open in the agent.',
    defaultKind: 'core.environment',
  ),
  AgentCreationRecipe(
    id: 'dotenv',
    title: 'Import a .env file',
    description:
        'Parse one dotenv file into protected and non-protected fields.',
    defaultKind: 'core.environment',
  ),
  AgentCreationRecipe(
    id: 'ssh_config',
    title: 'Read SSH config or alias',
    description: 'Capture one host and its related jump hosts from SSH config.',
    defaultKind: 'core.ssh_server',
    defaultSourcePath: '~/.ssh/config',
  ),
  AgentCreationRecipe(
    id: 'ssh_topology',
    title: 'Build bastion or tunnels',
    description:
        'Model related servers, ProxyJump hops, sudo, and port forwards.',
    defaultKind: 'core.ssh_server',
  ),
  AgentCreationRecipe(
    id: 'credential',
    title: 'Capture API or database access',
    description: 'Save one credential discussed in the current task.',
    defaultKind: 'core.api_credential',
  ),
  AgentCreationRecipe(
    id: 'prompt',
    title: 'Draft a reusable Prompt',
    description:
        'Turn the current goal and constraints into reusable agent instructions.',
    defaultKind: 'core.prompt',
  ),
  AgentCreationRecipe(
    id: 'runbook',
    title: 'Draft a Runbook or Note',
    description: 'Create durable operational steps or project knowledge.',
    defaultKind: 'core.runbook',
  ),
];

class AgentCreationHandoff {
  const AgentCreationHandoff({
    required this.id,
    required this.command,
    required this.expiresAt,
  });

  factory AgentCreationHandoff.fromJson(Map<String, dynamic> json) =>
      AgentCreationHandoff(
        id: json['handoff_id'] as String,
        command: json['command'] as String,
        expiresAt: DateTime.parse(json['expires_at'] as String).toLocal(),
      );

  final String id;
  final String command;
  final DateTime expiresAt;

  bool get expired => !expiresAt.isAfter(DateTime.now());

  String get clipboardText =>
      'Create this item in KeyLease. Run `$command` and follow the CLI instructions.';
}

class AgentCreationDraft {
  AgentCreationDraft({required String kind, String? groupId})
    : kind = kind,
      groupId = groupId,
      _initialKind = kind,
      _initialGroupId = groupId,
      sessionId = 'agent-new-${DateTime.now().microsecondsSinceEpoch}';

  final String sessionId;
  final String _initialKind;
  final String? _initialGroupId;
  String recipeId = 'describe';
  String kind;
  String? groupId;
  String? projectSlug;
  String tags = '';
  String agentAccess = 'read_write';
  String context = '';
  String sourcePath = '';
  Set<String>? baselineEntryIds;
  AgentCreationHandoff? handoff;
  bool handoffCopied = false;

  AgentCreationRecipe get recipe => agentCreationRecipes.firstWhere(
    (candidate) => candidate.id == recipeId,
    orElse: () => agentCreationRecipes.first,
  );

  bool get isAgentContent =>
      const {'core.prompt', 'core.runbook', 'core.note'}.contains(kind);

  bool get isDirty =>
      recipeId != 'describe' ||
      kind != _initialKind ||
      groupId != _initialGroupId ||
      context.trim().isNotEmpty ||
      sourcePath.trim().isNotEmpty ||
      tags.trim().isNotEmpty ||
      projectSlug != null ||
      agentAccess != 'read_write' ||
      handoffCopied;

  List<String> get parsedTags => tags
      .split(',')
      .map((tag) => tag.trim())
      .where((tag) => tag.isNotEmpty)
      .toList(growable: false);

  void invalidateHandoff() {
    handoff = null;
    handoffCopied = false;
  }

  void applyRecipe(AgentCreationRecipe next) {
    recipeId = next.id;
    kind = next.defaultKind;
    sourcePath = next.defaultSourcePath ?? '';
    invalidateHandoff();
  }
}
