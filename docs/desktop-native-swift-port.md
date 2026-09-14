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
| Golden vectors | `test-vectors/rpc/golden/` (25 file) | capture từ daemon thật, secrets đã scrub |
| Capture script | `scripts/capture-rpc-golden.py` | tạo vault/client/grant tạm, drive socket, ghi vector |

Test: `cd apps/desktop-macos && swift test` — 21 test, gồm:

- `WireCommandParityTests` — so `commands.json` (giống `parity.rs` bên Rust)
- `GoldenVectorTests` — replay 23 vector: request trên wire phải **bằng hệt**
  bản ghi; result/error typed đúng
- `ClientBehaviorTests` — token file, oversize, transport error
- `ContractModelsTests` — decode `EntryView`/`FieldValue`/`PolicyDecision`/…
  từ response thật

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

## Còn lại — cần máy Mac

### 1. Xcode project + shell (Phase 2)

- `apps/desktop-macos/KeyLease.xcodeproj`: app target `KeyLease`, bundle id
  khớp bản Flutter (`app.keylease.*`), deployment macOS 14, link local package
  `KeyLeaseCore`.
- `NavigationSplitView` shell: sidebar (Vault/Connections/Approvals/Activity/
  Migrations/Settings) + list/detail resizable — thay `adaptive_shell.dart`.
- Port design tokens từ `ui/tokens/keylease_tokens.dart` (~127 dòng) sang
  SwiftUI `Color`/`Font` extensions.

### 2. RuntimeService (port từ `MainFlutterWindow.swift` runtime channel)

- Gọi `keylease desktop inspect/provision/listVaults/createVault/switchVault/
  renameVault/inspectSource` qua `Process` — logic đã có sẵn, bỏ lớp
  MethodChannel.
- Embed `keylease` binary vào `Contents/Resources` (cargo build
  `x86_64-apple-darwin` + `aarch64-apple-darwin`, lipo universal2),
  `Contents/Library/LaunchAgents/app.keylease.service.plist`, đăng ký qua
  `SMAppService.agent` (kèm xử lý `BACKGROUND_APPROVAL_REQUIRED`).
- `vaultChanged` push: hiện tại helper không push; nếu giữ nguyên semantics
  thì app poll/publish giống Dart (`publishVaultChange` + distributed
  notification hoặc XPC giữa helper/app — xem lại cách channel hiện tại
  nhận event).

### 3. State layer

Port `core/state/` (~2.1k dòng Dart) sang `@Observable` classes:

- `AppController` (570) — phase machine, auth/session, lock triggers
- `VaultController` (787) — entries/groups/selection/reveal
- drafts (`entry_draft`, `agent_creation_draft`, `password_generator_settings`),
  `section_controllers`, `busy_registry`, `user_message`, `connection_settings`
- `PreferencesStore` → `UserDefaults`/`FileManager` tương đương
  `file_preferences_store.dart`

### 4. Features (~8.4k dòng Dart)

- Onboarding phases (`onboarding/phase_screens.dart`, 394)
- Vault: `entry_list` (221), `entry_detail` (791), `entry_editor` (1277),
  `password_generator` (490), `totp_dialog` (128), templates
  (`developer_templates` 406, `developer_template_detail` 489,
  `developer_template_editor` 1642 — file lớn nhất), `agent_driven_creation`
  (588), `template_guidance` (181)
- Connections (389) + `google_oauth_flow` (91)
- Approvals (148), Activity (130), Migrations (167), Settings (664) + multi-vault
- Components chung (~1.4k): `EntryRow`, `SecretField`, `RequestSummary`,
  `KeyLeaseDialog`, `SearchableSelect`, `SplitPane`, `MessageBanner`, …

### 5. SecurityService (port từ `MainFlutterWindow.swift` security channel)

- `NSPasteboard`: copy secret + clear sau 30s chỉ khi `changeCount` không đổi;
  clear khi sleep/screen-lock/manual lock.
- `NSWorkspace` sleep/wake + `DistributedNotificationCenter`
  (`com.apple.screenIsLocked`) → `lock` RPC.
- `NSOpenPanel` security-scoped cho client token file; SSH key discovery/picker.
- TOTP QR: chọn ảnh (`CIDetector`/Vision) + screen scan (`ScreenCaptureKit` +
  `SCContentSharingPicker`, xin quyền Screen Recording).
- `openGoogleAuthorization`: chỉ mở URL host `accounts.google.com`;
  `openExternalUrl` cho http(s) thường.
- Settings window riêng (SwiftUI `Settings` scene).

### 6. Menu bar + shortcut + polish

- SwiftUI `Commands`: ⌘F search, ⌘, settings, Vault menu ⌘N/⌘R/⌘L —
  đơn giản hơn nhiều so với retarget trong Flutter runner.
- Window size/position restore (`NSWindow.frameAutosaveName`).
- VoiceOver/accessibility audit; error surface theo `UserMessage` semantics.

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
