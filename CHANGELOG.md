# Changelog

All notable changes to KeyLease are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and KeyLease uses
[Semantic Versioning](https://semver.org/) (see docs/releasing.md). This file is
generated from commit messages by git-cliff.

## [0.2.1] - 2026-10-27

### Bug fixes

- **cli:** Create the vault and socket directories on a fresh host (#7) (abfc492)

## [0.2.0] - 2026-10-27

### Features

- **cloud:** Share items with VPS nodes, back up and recover through a cloud relay (#4) (c653acd)

### Continuous integration

- Build an ad-hoc signed macOS DMG for every release (#5) (eec7c4b)

### Other

- Remove the Flutter desktop app (#3) (4888311)

## [0.1.0] - 2026-10-27

### Features

- Implement LeaseGate phase 0 and phase 1 MVP (b886205)
- Implement Phase 2 and Phase 3 beta (0507164)
- Implement phase 4 connector platform and policy UX (0fa4212)
- Add self-hosted dynamic credential gateway (6a9377c)
- Implement phase 6 enterprise self-hosting (723e2e0)
- Harden single-vps production profile (b294d29)
- Automate single-vps phase 8 operations (5ba15a1)
- Add single-vps phase 9 onboarding (5c8ce05)
- **ui:** Add Forui migration plan and spikes (48e5f76)
- **ui:** Migrate the desktop client to Forui 0.26 (798806c)
- Add managed desktop runtime and vault UX (69249f3)
- Expand vault templates and desktop workflows (ee90604)
- **desktop:** Add developer vault templates (0a6df79)
- **desktop:** Streamline vault copy actions (695522d)
- **desktop:** Explain vault templates (65e60d6)
- **desktop:** Add agent-driven item creation (1ec70a0)
- **agent:** Add CLI-backed new-item handoffs (acce2f6)
- **mobile:** Add an in-process vault core for Android (a43f50e)
- **android:** Add the Leasegate Vault app (e3ac393)
- **desktop:** Add the native Swift KeyLeaseCore package (b2a0ead)
- **desktop:** Add the SwiftUI app shell and .app packaging (34a2644)
- **desktop:** Port the full Flutter vault surface to native SwiftUI (6c0b010)
- Mobile biometric vault integration and UI updates (ef56ffa)
- **desktop:** Modernize the macOS UI with a brand design system (f860c0c)
- **desktop:** Add menu-bar quick access and drag-to-group filing (07c134d)
- **mobile:** Add native Kotlin/Compose Android app alongside Flutter (4b5f086)
- **macos:** Support custom fields and idle lock recovery (073305a)
- Add project organization for vault items (4332e4d)
- Add vault approvals, agent enrollment and time-boxed trust (20d4b95)
- Add a KeyLease SSH agent and headless unlock for VPS hosts (8b1feca)
- Add a PostgreSQL proxy that never holds the database password (9cce2e8)
- Add paired remote approvers for headless vault nodes (67cff66)
- Add keylease run for injecting secrets into a child process (cc1e3f8)
- Add the macOS trust picker, agent enrollment and remote vault approver (15228c8)
- Add an MCP server and a self-hosted OAuth MCP gateway (b400aa0)
- Add contributor guide, CI and issue templates (8d695d3)

### Bug fixes

- Fix macOS Intel Rust host check (2cec41a)
- **desktop:** Sync vault switches across windows (5780c29)
- **desktop:** Resolve SSH keys before config copy (b7552d0)
- **desktop:** Focus newly added SSH forms (9038783)
- **desktop:** Explain rejected master passwords (5ec8609)
- **desktop:** Show unlock errors inline (04a5971)
- **desktop:** Clarify pending agent creation (dc5c5e0)
- **kdbx:** Keep field order stable across import (1f13fba)
- **desktop:** Build native app with Swift 6 (6ad274f)
- **desktop:** Restore Swift 6 release build (2576735)
- **desktop:** Enlarge form controls and pin scrollbars to the edge (5fde4a7)
- **desktop:** Guard drafts, confirm copies, and surface pending approvals (4387544)
- **desktop:** Unify master-password fields under one secure-field style (7724588)
- **desktop:** Reuse the main window from menu-bar quick access (c1a51bc)
- **desktop:** Center section empty and loading states (38f5779)
- **mobile:** Detect an uninitialised vault and identify it on the lock screen (7ebe7c0)
- **mobile:** Finish vault mutations after their screen leaves composition (752546a)
- **mobile:** Submit credential forms from the keyboard action key (8fff23f)
- Fix macOS TOTP scanning and short-secret URI saves (7e11a29)
- Preserve macOS screen capture grants with stable local signing (d486c62)
- Close gaps found in an independent review of the trust layer (9fb4470)
- Close gaps found in an independent review of the MCP tools and gateway (6a4bf8f)

### Performance

- Smooth desktop dialogs and selects (e4e57d5)

### Refactoring

- **flutter:** Extract the shared vault client into a package (110b625)
- **desktop:** Move Migrations into Settings, demote Connections (f43be0b)

### Documentation

- Document Phase 3 self-hosted architecture (80e9036)
- Record the mobile trust boundary (5dfab5c)
- Document the architecture and practical agent setups (1ccc2fe)

### Continuous integration

- Add the tag-driven release pipeline and crates.io publishing (#1) (364b6d9)

### Dependencies

- Update dependencies with security advisories and check them in CI (87bf0b3)

### Other

- Initialize Flutter binding before desktop adapters (5869a98)
- Propose ADR 0005 for agent trust and secret use without disclosure (802b345)
- Point agent prompts and the README at the secret brokers (84b89e3)
- Prepare the repository for open source (500b2b9)
- Remove Vietnamese planning notes and point at the personal repository (b057cb3)
- Point at the renamed keylease repository (5304d6e)


