# KeyLease Flutter UI spikes

**Quyết định 2026-09-07:** chọn Forui cho production. Spike `macos_ui` được giữ
làm đối chứng về macOS shell, không phải hướng implementation tiếp theo.

Hai spike dùng cùng model và cùng widget nghiệp vụ list/detail để so sánh phần
shell và controls của `macos_ui` với Forui. Chúng dùng fixture, không gọi IPC,
đọc token, copy clipboard hoặc thay đổi entry point production `lib/main.dart`.

## Chạy

Từ `apps/desktop-flutter`:

```sh
flutter config --enable-swift-package-manager
flutter pub get
flutter run -d macos -t lib/ui_spikes/macos_ui_spike.dart
flutter run -d macos -t lib/ui_spikes/forui_spike.dart
```

Kiểm tra code và build:

```sh
flutter analyze lib/ui_spikes test/ui_spikes_test.dart
flutter test test/ui_spikes_test.dart
flutter build macos --debug -t lib/ui_spikes/macos_ui_spike.dart
flutter build macos --debug -t lib/ui_spikes/forui_spike.dart
```

Hai lệnh build cùng ghi vào `build/macos/Build/Products/Debug/KeyLease.app`;
build sau thay artifact của build trước.

## Phạm vi so sánh

| Phần | macos_ui | Forui |
| --- | --- | --- |
| App/shell | MacosApp, MacosWindow, MacosScaffold | MaterialApp + FTheme, FScaffold |
| Sidebar | Sidebar, SidebarItems | FSidebar, FSidebarGroup, FSidebarItem |
| Toolbar | ToolBar và toolbar item | FHeader, FHeaderAction, FButton |
| Search | MacosSearchField | FTextField + managed control |
| Pane | ResizablePane + ContentArea | LayoutBuilder + Row custom |
| List/detail | Shared custom widgets | Shared custom widgets |

Spike kiểm tra chọn item, search, reveal password mẫu, sidebar, desktop density,
dependency resolution, analyzer và build native macOS. Nó chưa kiểm tra IPC,
native clipboard, menu bar, VoiceOver, light/dark đầy đủ hoặc mobile runner.

## Dependency và build finding

- Máy thực hiện spike: Flutter 3.41.4, Dart 3.11.1.
- `macos_ui` 2.2.2 yêu cầu Flutter >=3.35 và thêm các plugin macOS.
- `macos_ui` không build được khi Flutter tự tạo CocoaPods integration nhưng
  máy không có CocoaPods executable. Spike đã được build với Flutter setting
  `enable-swift-package-manager: true`; generated package nằm dưới thư mục
  `macos/Flutter/ephemeral`. Không sửa `MainFlutterWindow.swift`, nên security
  adapter hiện có vẫn nguyên vẹn. CI và máy developer cần bật setting trên.
- Forui mới nhất tại thời điểm spike là 0.26.0 nhưng yêu cầu Flutter >=3.47.
  Spike pin 0.21.3, bản mới nhất tương thích Flutter 3.41.x trên máy này.
- Tài liệu release của repo yêu cầu Flutter 3.47.2 trên Intel. Trước khi chọn
  Forui production, nâng spike lên 0.26.x bằng đúng toolchain đó, chạy migration
  và lặp lại analyze/test/build.
- Forui đang ở version 0.x và changelog có breaking changes. Pin version và
  dành bước migration rõ ràng thay vì tự động nhận update.

Kết quả xác minh trên máy spike: full `flutter analyze` pass, toàn bộ 4 widget
tests pass, và debug build của cả hai entry point pass. Mỗi build được thực hiện
riêng vì dùng chung output app bundle.

## Đánh giá ban đầu

`macos_ui` cho shell macOS trực tiếp hơn và có ResizablePane, nhưng thêm plugin
native chỉ dành cho macOS. Forui cho một hệ component và theme dùng được trên
tất cả target Flutter, có phân biệt touch/desktop và platform variants. Trong
spike, split pane vẫn là layout custom vì tính đồng bộ component không tự giải
quyết information architecture theo kích thước màn hình.

Forui là baseline đã chọn cho một codebase đa nền tảng. Giữ cùng model,
permission copy và feature contracts; thay shell theo form factor:

- desktop: sidebar + list/detail, hover, keyboard, window/menu adapter;
- tablet: navigation rail/sidebar có thể thu gọn + list/detail;
- phone: bottom navigation hoặc compact navigation + list → detail route;
- macOS/Windows: bổ sung menu/window integration riêng, dù controls dùng Forui.

Không dùng `macos_ui` song song trong production vì cách đó tăng số
implementation và ma trận test. Trong phase foundation, dependency này sẽ được
loại khỏi production dependency hoặc cô lập hoàn toàn như mã tham chiếu.
