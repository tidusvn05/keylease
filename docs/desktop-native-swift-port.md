# Port desktop macOS sang native Swift — trạng thái và việc còn lại

Tài liệu này theo dõi việc port `apps/desktop-flutter` sang app macOS native
(Swift + SwiftUI). Quyết định đã chốt (2026-09-14):

- **macOS 14+** làm deployment target — dùng `@Observable` và SwiftUI hiện đại.
- **Full parity một lần**: không release MVP; cửa release duy nhất là đủ
  parity với bản Flutter.
- **Duy trì Flutter song song**: `apps/desktop-flutter` không xóa sau khi xong;
  package `leasegate_vault_ui` vẫn là nguồn tham chiếu design cho mobile.

## Nguyên tắc kiến trúc

Rust daemon (`keylease serve`) vẫn là boundary duy nhất cho crypto, policy và
persistence. App Swift chỉ là presentation client, giống hệt vai trò của bản
Flutter: nói chuyện với daemon qua Unix socket, framing line-delimited JSON,
envelope `{"ok": bool, "result" | "error"}`.

Không dùng FFI/in-process cho desktop — daemon socket giữ nguyên trust model
(vault lock/unlock, approval flow, audit) và cho phép `keylease` binary được
embed + chạy như hiện tại.

## Đã làm xong (chạy và test được trên cả Linux)

`apps/desktop-macos/` — SwiftPM package `KeyLeaseCore`:

| Thành phần | File | Ghi chú |
|---|---|---|
| Generated models | `Sources/KeyLeaseCore/Generated/ContractModels.swift` | 50 type `Codable` từ `keylease contracts` (schemars) — không sửa tay |
| Codegen | `scripts/generate-swift-contracts.py` | JSON Schema → Swift; fail-fast với construct mới |
| Wire request | `Sources/KeyLeaseCore/RpcRequest.swift` | 51 command, tagged `"command"`; auth được splice lúc gọi |
| Transport | `Sources/KeyLeaseCore/KeyLeaseRpc.swift` | POSIX AF_UNIX, 1 connection/call, 4 MiB bound, timeout 10s/30s |
| Token file | `Sources/KeyLeaseCore/ClientTokenFile.swift` | regular file (lstat), ≤4 KiB, mode 0600 |
| Errors | `Sources/KeyLeaseCore/KeyLeaseError.swift` | mirror `KeyLeaseErrorCode` phía Dart |
| Dynamic JSON | `Sources/KeyLeaseCore/JSONValue.swift` | tương đương `Map<String,dynamic>` của Dart |
| `PasswordRecipe` | `Sources/KeyLeaseCore/PasswordRecipe.swift` | viết tay — chưa nằm trong contracts output |
| `EntryDraft` | `Sources/KeyLeaseCore/EntryDraft.swift` | port `entry_draft.dart` — create/edit payload, `ifRevision`, isDirty, validation, agent-content |
| Template fields | `Sources/KeyLeaseCore/TemplateFields.swift` | standard/custom field map, typed value, validation, guidance, fallback templates |
| Dev templates | `Sources/KeyLeaseCore/DeveloperTemplates.swift` | `parseDotEnv`/`renderDotEnv`, SSH endpoints/forwards state + `renderSshConfig`, `resolveSshPrivateKeyPaths` |
| Agent creation | `Sources/KeyLeaseCore/AgentCreation.swift` | recipes, `AgentCreationDraft`, handoff input + clipboard text |
| Password gen | `Sources/KeyLeaseCore/PasswordGeneratorSettings.swift` | settings + entropy/strength giống Dart |
| Presentation | `Sources/KeyLeaseCore/VaultPresentation.swift` | `FieldView.displayValue`, monogram/subtitle, `EntryRevision`, `TotpCode`, structured-id helpers |
| Golden vectors | `test-vectors/rpc/golden/` (25 file) | capture từ daemon thật, secrets đã scrub |
| Capture script | `scripts/capture-rpc-golden.py` | tạo vault/client/grant tạm, drive socket, ghi vector |

`apps/desktop-macos-app/` — SwiftPM executable `KeyLease` (SwiftUI, macOS 14),
package riêng trỏ về `KeyLeaseCore` để Linux CI không đụng code Darwin:

| Thành phần | File | Ghi chú |
|---|---|---|
| App shell | `Sources/KeyLease/KeyLeaseApp.swift` | `@main`, WindowGroup + `Settings` scene, menu Vault ⌘N/⇧⌘G/⌘R/⌘L |
| Phase machine | `Sources/KeyLease/AppController.swift` | port `AppController`: starting → inspect → service → locked → ready; copy/prompt/CLI helpers, managed vaults, SSH bindings |
| Vault state | `Sources/KeyLease/VaultController.swift` | full port: search/list/`entries_view`/reveal/draft/save/delete/groups/migrations/history/TOTP/agent creation |
| Section state | `Sources/KeyLease/SectionControllers.swift` | connections, approvals (stale re-check), activity |
| Preferences | `Sources/KeyLease/PreferencesStore.swift` | `~/.keylease/ui.json` — password settings, SSH key bindings |
| Host integrations | `Sources/KeyLease/HostIntegrations.swift` | `NSOpenPanel`, `~/.ssh` key discovery, Vision QR scan, ScreenCaptureKit TOTP scan |
| RuntimeService | `Sources/KeyLease/RuntimeService.swift` | port `LocalRuntimeBridge` — Process + `SMAppService.agent`, fallback daemon tách rời khi `swift run` |
| SecurityService | `Sources/KeyLease/SecurityService.swift` | `NSPasteboard` copy + clear 30s, sleep/screen-lock → `lock`, openExternalUrl/Google host check |
| Views | `Sources/KeyLease/Views/` | RootView phase router; Unlock; Onboarding (create + import/adopt/restore); Repair; ContentView (section rail + group tree); VaultListView; EntryDetailView (reveal/TOTP/notes/history); EntryEditorView (create/edit/templates/dev-templates/agent mode); DeveloperTemplateViews (env + SSH editor/detail); UtilityPanes (password generator + agent creation); SectionViews (connections/approvals/activity/migrations); SettingsView (general/vaults/security) |
| Packaging | `scripts/package-macos-swift.sh` | `swift build` universal2 → `.app` bundle (không cần .xcodeproj) → tái dùng `prepare-macos-runtime.sh` cho helper + plist → codesign → `--install` thay `/Applications` |

Test: `cd apps/desktop-macos && swift test` — 62 test, gồm:

- `WireCommandParityTests` — so `commands.json` (giống `parity.rs` bên Rust)
- `GoldenVectorTests` — replay 23 vector: request trên wire phải **bằng hệt**
  bản ghi; result/error typed đúng
- `ClientBehaviorTests` — token file, oversize, transport error
- `ContractModelsTests` — decode `EntryView`/`FieldValue`/`PolicyDecision`/…
  từ response thật
- `EntryDraftTests` — create/update payload, `ifRevision`, blank-secret =
  keep, content payloads
- `DeveloperTemplateTests` — `.env` parse/render, SSH config render + quote
  rules, structured field/section sync, key-path resolution
- `PasswordGeneratorAndAgentTests` — entropy/strength, recipe → RPC shape,
  agent handoff input/expiry

Regenerate khi contract đổi:

```sh
cargo run -p keylease-cli -- contracts > /tmp/contracts.json
scripts/generate-swift-contracts.py /tmp/contracts.json \
    apps/desktop-macos/Sources/KeyLeaseCore/Generated/ContractModels.swift
# nếu đổi wire behavior: python3 scripts/capture-rpc-golden.py
```

Toolchain trên VPS: Swift 6.2.4 debian12 tarball tại
`~/.local/share/swift-toolchain/6.2.4/` (mise chưa có build debian13).
Trên Mac: Xcode ≥16 là đủ.

## Parity checklist với bản Flutter

Checklist này phản ánh `packages/leasegate_vault_ui` (~15k dòng Dart). Trạng
thái: ✅ xong · 🚧 đã port, chưa verify trên máy Mac · ⬜ chưa làm.

### Vòng đời app / phase machine

- ✅ starting → inspect → ensureService → status → ready (AppController)
- ✅ onboarding (`mode: "create"` + import KDBX/1PUX/backup/adopt database
  qua `inspectSource`), provisioning, repair (`repair_desktop_client`)
- ✅ backgroundApprovalRequired, serviceUnavailable, locked, permissionDenied
- ✅ lock on sleep + screen lock + ⌘L; clipboard clear theo changeCount

### Vault list & navigation

- ✅ Groups sidebar: All items / Favorites / cây group 2 cấp / New group /
  Manage groups (reorder, rename, delete empty)
- ✅ Search debounce 220ms, stale-response guard, count header, empty states
- ✅ Favorite filter, group filter (kể cả subgroup), selection normalize,
  arrow-key move
- ✅ Password generator pane + settings (persist `~/.keylease/ui.json`)

### Entry detail

- ✅ Identity + actions (favorite, edit, delete, copy prompt, copy CLI)
- ✅ Login details (username/password/website) + reveal/hide/copy
- ✅ Field-oriented view `entries_view`: sections, semantic roles,
  `entries_reveal`/`entries_reveal_by_id`/`entries_reveal_many`
- ✅ Reveal timeout 15s + hide on lock/sleep/select đổi
- ✅ TOTP inline với countdown + copy; notes fetch/copy; metadata +
  `entries_history`
- ✅ Developer template detail: `.env` copy/search, SSH config copy
  (per-device key binding, `resolveSshPrivateKeyPaths` + `renderSshConfig`)

### Edit / create — yêu cầu chính

- ✅ `EntryDraft` port: create/edit init, `isDirty`, validation
  (title/group/JSON fields/JSON sections)
- ✅ `entries_create` / `entries_update` với `if_revision` +
  `idempotency_key` + `dry_run: false`; secret trống = "giữ giá trị cũ"
- ✅ `content_create` / `content_update` / `content_set_access` cho
  `core.prompt` / `core.runbook` / `core.note` (tags, project, agent access)
- ✅ Editor pane: template picker + guidance, group picker, title, favorite,
  dynamic template fields (typed value + validation), password generate /
  reveal, TOTP (base32/otpauth + QR scan), notes markdown, tags/project,
  custom JSON fields fallback
- ✅ Developer template editor: `core.environment` (paste .env, parse, biến
  secret/visible, reorder) + `core.ssh_server` (endpoints, forwards, key
  binding per device)
- ✅ Delete entry (revision-checked, confirm), favorite toggle,
  revision-conflict → draft giữ nguyên để retry
- ✅ Dirty-draft confirm trước khi đổi selection/đóng editor
- ✅ Agent-driven creation: recipe cards, handoff `agent_handoff_create`,
  copy CLI command, refresh & review `entriesCreatedSince`

### Các section khác

- ✅ Connections: list, test/refresh/disconnect/revoke, enroll/unenroll
  resource, add token connection, Google OAuth flow
- ✅ Approvals: list pending, request summary, approve/deny với
  stale-request re-check
- ✅ Activity: `audit_query`, filter denied/failed, friendly time
- ✅ Migrations: `migrations_status` banner, preview proposals, apply với
  digest, rollback checkpoint
- ✅ Settings: General (data folder, migrations, restart service, repair) /
  Vaults (create/rename/switch/import) / Security — `Settings` scene tabs;
  Connections/Activity vẫn nằm trong section rail chính

### Host capabilities (SecurityService + HostIntegrations)

- ✅ Clipboard copy + timed clear, lock signals, http(s) + Google URL guard
- ✅ `NSOpenPanel` vault-source/SSH key/QR image pickers; `~/.ssh` private
  key discovery (header sniff)
- ✅ TOTP QR: image picker (Vision) + screen scan
  (`SCScreenshotManager`/`SCContentSharingPicker` khi có), Screen Recording
  settings deep-link
- ⬜ `publishVaultChange` / distributed notification giữa nhiều window
- ⬜ VoiceOver/accessibility audit; menu bar polish; frame autosave
- ⬜ Packaging/notarize + release gate (chạy `package-macos-swift.sh`,
  `docs/macos-x86_64-build-test.md` trên máy Mac)

## Còn lại — cần máy Mac

### 1. Shell hoàn chỉnh (Phase 2)

- ~~Xcode project~~ → đã chọn **SwiftPM executable + `package-macos-swift.sh`**,
  không cần `.xcodeproj` trong git.
- `NavigationSplitView` shell đã có (milestone 1); còn: port design tokens từ
  `ui/tokens/keylease_tokens.dart` (~127 dòng) sang SwiftUI `Color`/`Font`
  extensions, polish layout theo `docs/macos-ui-ux-improvement-plan.md`.

### 2. RuntimeService (port từ `MainFlutterWindow.swift` runtime channel)

- ✅ `inspect/provision/listVaults/createVault/switchVault/renameVault/
  inspectSource` qua `Process` + `SMAppService.agent` (xử lý
  `BACKGROUND_APPROVAL_REQUIRED`) — `RuntimeService.swift`.
- ✅ Embed helper: `package-macos-swift.sh` tái dùng `prepare-macos-runtime.sh`
  (universal2 + `Contents/Library/LaunchAgents` plist + codesign).
- Còn: `vaultChanged` push giữa nhiều window/instance — `publishVaultChange`
  + distributed notification (hoặc XPC). Milestone 1 chỉ có 1 window nên
  chưa cần.

### 3. State layer — ✅ đã port

- ✅ `AppController` — phase machine, auth/session, lock triggers, copy/prompt/
  CLI helpers, managed vaults, SSH key bindings
- ✅ `VaultController` — entries/groups/selection/reveal/draft save/delete,
  migrations, history, TOTP, agent-driven creation
- ✅ drafts (`EntryDraft`, `AgentCreationDraft`, `PasswordGeneratorSettings`)
  trong `KeyLeaseCore`; `SectionControllers` (connections/approvals/activity),
  `UserMessage` inline trong `AppController`
- ✅ `PreferencesStore` → `~/.keylease/ui.json` tương đương
  `file_preferences_store.dart`

### 4. Features — ✅ đã port, chờ verify trên Mac

- ✅ Onboarding phases (create + import/adopt/restore)
- ✅ Vault: entry list, detail (reveal/TOTP/notes/history), editor
  (create/edit, dynamic template fields, dev-template env + SSH editors),
  password generator + settings sheet, TOTP dialog flow, agent-driven
  creation pane, template guidance
- ✅ Connections + Google OAuth flow; Approvals (stale re-check); Activity;
  Migrations; Settings + multi-vault
- ✅ Components chung trong `Views/ViewSupport.swift`: GuidanceCard,
  FieldRows, monogram, message banner, confirm helpers
- Còn: polish layout + design tokens trên máy Mac thật

### 5. SecurityService (port từ `MainFlutterWindow.swift` security channel)

- ✅ `NSPasteboard` copy + clear 30s theo `changeCount`; clear khi
  sleep/screen-lock/manual lock (`SecurityService.swift`).
- ✅ `NSWorkspace.willSleepNotification` + `com.apple.screenIsLocked` → `lock`
  RPC; `openGoogleAuthorization` chỉ `accounts.google.com`, `openExternalUrl`
  chỉ http(s); `Settings` scene tối thiểu đã có.
- ✅ `NSOpenPanel` cho vault-source/SSH key/QR image (`HostIntegrations.swift`);
  `~/.ssh` private-key discovery (header sniff); TOTP QR qua Vision +
  ScreenCaptureKit (`SCScreenshotManager`/`SCContentSharingPicker` theo OS),
  deep-link Screen Recording settings.

### 6. Menu bar + shortcut + polish

- ✅ SwiftUI `Commands`: Vault menu ⌘N (new item), ⇧⌘G (password generator),
  ⌘R (refresh), ⌘L (lock); arrow-key navigation trong list.
- Còn: ⌘F search focus, window size/position restore
  (`NSWindow.frameAutosaveName`), VoiceOver/accessibility audit, error
  surface theo `UserMessage` semantics.

### 7. Packaging + release gate

- `scripts/build-install-macos-swift.sh` tương đương bản Flutter:
  cargo build keylease (universal2) → embed → codesign app + helper →
  (tùy chọn) notarize → replace `/Applications/KeyLease.app` an toàn.
- Parity checklist dựa trên `docs/macos-ui-ux-improvement-plan.md` + chạy
  `docs/macos-x86_64-build-test.md` tương đương cho bản Swift.

## Chống drift với bản Flutter (vì duy trì song song)

- `commands.json` + generated models là nguồn chung duy nhất; sửa tay
  `ContractModels.swift` là cấm — chạy codegen.
- Thay đổi UI flow → PR phải chạm cả hai app, hoặc ghi rõ vào parity
  checklist trước release.
- Khi thêm RPC command: thêm vào `commands.json` + `RpcRequest` Swift +
  Dart client trong cùng commit (Rust `parity.rs` và
  `WireCommandParityTests` cùng gãy nếu thiếu).
