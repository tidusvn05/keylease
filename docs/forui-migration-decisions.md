# Quyết định trong migration Forui

Ngày: 2026-09-07. Phạm vi: `apps/desktop-flutter`. Xem kế hoạch và checklist ở
[docs/macos-ui-ux-improvement-plan.md](macos-ui-ux-improvement-plan.md).

Tài liệu này ghi các quyết định phải chốt trong lúc triển khai, kèm bằng chứng.
Nó không thay thế kế hoạch.

## Toolchain và version đã pin

| Hạng mục | Giá trị | Ghi chú |
| --- | --- | --- |
| Flutter | 3.47.2 stable (Dart 3.13.2) | Đúng release baseline của repo |
| Forui | `0.26.0` (pin chính xác, không dùng `^`) | Bản mới nhất dòng 0.26.x |
| material_ui | `1.1.1` | Bắt buộc, xem dưới |

Forui vẫn ở `0.x`; mỗi lần nâng phải đọc changelog và cập nhật mục này.

## Breaking change đã xử lý khi lên 0.26.0

Nguồn: `CHANGELOG.md` của package (0.22.0 → 0.26.0).

| Thay đổi | Xử lý trong repo |
| --- | --- |
| **0.26.0** bỏ `flutter/material.dart`, chuyển sang package `material_ui` | Toàn bộ app và spike import `package:material_ui/material_ui.dart`. Bắt buộc: `FThemeData.toApproximateMaterialTheme()` trả về `ThemeData` của `material_ui`, không tương thích kiểu với `ThemeData` trong `flutter/material.dart` |
| **0.26.0** đổi tên `forui_assets` thành `forui_lucide` | Icon Lucide dùng `FLucideIcons.<name>` |
| **0.24.0** xóa `FThemes` | Dùng `FTheme.neutral.light/dark` × `.desktop/.touch` |
| **0.24.0** xóa color scheme dựng sẵn, chỉ còn `FColors.neutralLight/neutralDark` | `KeyLeaseTheme` dựng `FThemeData` từ neutral + `colors.copyWith(primary/primaryForeground/error)` theo token KeyLease |
| **0.22.0** biến `FIcons` thành bộ *token* icon trên `FThemeData.icons` | `FIcons.folder` cũ → `FLucideIcons.folder` |
| **0.24.0** `FDialog` và `FCard` bỏ layout dựng sẵn | KeyLease tự sở hữu layout dialog: `lib/ui/components/keylease_dialog.dart` |
| **0.23.0** `FTypography` tách thành `body`/`display` | Dùng `typography.body.sm`, `typography.display.xl`… |

`FThemeData` không có `copyWith`, nên theme được dựng lại từ `FThemeData(...)`
và cache theo `(brightness, density)`.

## macos_ui đã rời khỏi production

- `pubspec.yaml` không còn `macos_ui`. `flutter pub deps` xác nhận
  `macos_ui`, `macos_window_utils`, `appkit_ui_element_colors` đã biến mất khỏi
  dependency graph.
- `macos/Flutter/GeneratedPluginRegistrant.swift` không còn plugin nào.
- **Hệ quả tích cực:** app không còn plugin native nào, nên
  `flutter config --enable-swift-package-manager` (bắt buộc trước đây vì
  `macos_ui` sinh CocoaPods integration) **không còn cần thiết** cho CI hoặc
  máy developer.
- Source spike đối chứng được archive tại `apps/desktop-flutter/spikes/macos_ui/`,
  nằm ngoài `lib/`, được `analysis_options.yaml` loại trừ và không được build.

## Fields prototype đề xuất nhưng IPC không có

Kiểm tra `crates/keylease-core/src/domain.rs`, `connection.rs`, `audit.rs` và
`crates/keylease-cli/src/main.rs`. Quyết định: **bỏ khỏi UI**, không tạo dữ liệu giả.

| UI trong prototype | Bằng chứng | Quyết định |
| --- | --- | --- |
| Favorites (sao trên từng entry) | `ItemMetadata` chỉ có `id, group_id, kind, title, username, urls, revision, updated_at` | Bỏ. Cần thêm field vào contract mới làm được |
| "Recently used" ordering | `search_entries` trả về thứ tự của store, không có tín hiệu recency | Bỏ. List giữ nguyên thứ tự daemon trả |
| Badge TOTP trên entry row | `ItemMetadata` không cho biết entry có TOTP | Bỏ badge. Mã TOTP vẫn lấy theo yêu cầu qua `entries_totp` |
| Tên client dễ đọc | Approval/audit chỉ có `agent_id` | Hiển thị `agent_id` |
| "Reason" tự do của approval | `ApprovalRecord` không có; nhưng **có** `risk`, `semantic_summary.operation/target/changed_fields/blast_radius` | Dùng đúng các field có thật thay cho reason bịa |

Ngược lại, các field có sẵn nhưng UI cũ bỏ phí đã được đưa vào:
`ConnectionRecord.health_reason`, `reauthorization_required`,
`granted_permissions`, `last_checked_at`; `ApprovalRecord.risk` và
`semantic_summary`.

## Trạng thái ứng dụng không còn gộp

`AppPhase` (`lib/core/state/app_phase.dart`) tách hẳn: `checking`,
`setupRequired`, `serviceUnavailable`, `locked`, `permissionDenied`, `ready`.
Vault có thêm `empty` và `searchEmpty` (`VaultListState`).

Cách phân biệt, dựa trên contract lỗi `{"ok":false,"error":{"error":"<code>"}}`
(`crates/keylease-core/src/error.rs`):

1. Thiếu client id/token file → `setupRequired` (chưa gọi IPC).
2. Không mở được socket → `serviceUnavailable` (`KeyLeaseErrorCode.transport`).
3. `status.locked == true` → `locked`.
4. Đã unlock nhưng probe `groups_list` trả `denied` → `permissionDenied`.
5. Còn lại → `ready`.

## Phát hiện về menu native macOS

`macos/Runner/Base.lproj/MainMenu.xib` mặc định của Flutter đã có
`Find… ⌘F` và `Preferences… ⌘,`. Trên macOS, AppKit tiêu thụ key equivalent của
menu **trước khi** Flutter view nhận sự kiện, nên shortcut Cmd+F và Cmd+, khai
báo trong `Shortcuts` của Flutter sẽ không bao giờ chạy.

Xử lý trong `macos/Runner/MainFlutterWindow.swift`:

- retarget hai menu item đó sang `keyLeaseMenuAction(_:)`, gửi
  `menuAction` qua channel `com.keylease/security`;
- thêm menu **Vault** (New Item ⌘N, Refresh ⌘R, Lock Vault ⌘L) bằng code, không
  sửa `.xib`;
- `setFrameAutosaveName("KeyLeaseMainWindow")` để khôi phục kích thước/vị trí cửa sổ.

Phía Dart, `MenuAction` chạy đúng các intent như accelerator trong app
(`lib/app/keylease_app.dart`), và có widget test.

**Chưa xác minh:** phần Swift này chưa được compile/chạy vì phiên triển khai
diễn ra trên Linux. Xem phần "chưa kiểm chứng" trong kế hoạch.

## Shortcut phải nằm trên Navigator

`Shortcuts` đặt trong `home:` không bao giờ được gọi: key event đi từ node đang
focus **lên trên**, mà focus scope của route nằm phía trên `home`. Vì vậy
accelerator được đăng ký qua `MaterialApp(shortcuts:, actions:)`, hợp nhất với
`WidgetsApp.defaultShortcuts/defaultActions` (nếu truyền vào, WidgetsApp sẽ
thay thế toàn bộ map mặc định).

## Ghi chú UX có bằng chứng

- `EntryRow` chỉ dùng `onPress`. Nếu gắn thêm `onDoubleTap`, mọi cú click đơn
  phải chờ hết double-tap timeout mới chọn được item.
- Action row của editor nằm ngoài vùng cuộn của dialog, nếu không nút Save rơi
  ra ngoài màn hình ở cửa sổ 800×600.

## Preferences lưu trên máy

`lib/core/platform/preferences_store.dart` ghi JSON (mode 0600) tại
`~/Library/Application Support/KeyLease/desktop-ui.json` (macOS). Nội dung chỉ
gồm: đường dẫn socket, client id, **đường dẫn** file token, và độ rộng pane.
Không có secret, không có master password, không có nội dung token.
