# Managed vault profiles

The desktop app keeps a metadata-only registry at `~/.keylease/vaults.json`.
The existing `~/.keylease/keylease.sqlite` vault remains the `primary` profile;
it is not moved or rewritten when profiles are enabled.

New profiles live under `~/.keylease/vaults/<profile-id>/`. Each profile owns
its encrypted database, desktop client token, backups, and master password.
The Unix socket remains stable at `~/.keylease/run/keylease.sock`, so local
clients do not need a new endpoint after a switch.

The registry contains only profile identifiers, display names, relative paths,
and the active profile identifier. It is written atomically with mode `0600`.
Relative paths are validated and may not escape the managed KeyLease home.

Switching profiles locks and clears the current session, changes the active
registry entry, restarts the background service, and leaves the target vault
locked. If restart fails, the desktop app restores the previous active profile
and restarts that service. Profile deletion is intentionally not available in
the first version.

The bundled CLI resolves its default database and desktop token through the
same active registry. Explicit `--db` and `--client-token-file` arguments still
take precedence.
