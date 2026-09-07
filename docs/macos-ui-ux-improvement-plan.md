# Kế hoạch cải thiện UI/UX KeyLease

Ngày cập nhật: 2026-09-07. Trạng thái: **Phase 0–3 và Phase 5 (mức fixture) đã
triển khai và kiểm chứng bằng analyze/test trên Flutter 3.47.2. Phase 4 chỉ hoàn
tất phần kiểm chứng được ngoài macOS; các mục cần Mac thật vẫn mở.**

Quyết định phát sinh trong lúc triển khai được ghi ở
[docs/forui-migration-decisions.md](forui-migration-decisions.md).

## Quyết định đã chốt

- Dùng **Forui** làm component library và nền tảng design system chung.
- Dùng một codebase Flutter cho Android, iOS, macOS và Windows; Linux/web có
  thể dùng cùng nền tảng nếu được đưa vào phạm vi phát hành sau này.
- macOS là nền tảng triển khai và nghiệm thu đầu tiên.
- Giữ Rust daemon và IPC hiện tại; UI không sở hữu crypto, KDBX parsing,
  policy hoặc quyết định cấp quyền.
- Giữ prototype HTML làm visual/interaction reference.
- Giữ native adapter riêng cho các khả năng của hệ điều hành: window/menu,
  clipboard, file access, sleep/screen lock và OAuth browser flow.
- Không dùng `macos_ui` trong implementation production. Spike của nó chỉ còn
  là bằng chứng so sánh và sẽ được tách khỏi dependency production hoặc lưu
  ở vùng thử nghiệm trước khi hoàn tất migration.

Lý do: Forui cung cấp cùng hệ component, theme `touch`/`desktop` và platform
variants cho các target Flutter. Nó giảm số bộ UI phải duy trì. Bố cục và luồng
vẫn thích ứng theo form factor; không ép sidebar desktop lên điện thoại.

## Trạng thái hiện tại

| Hạng mục | Trạng thái | Bằng chứng |
| --- | --- | --- |
| Đánh giá source UI cũ | Hoàn tất | Material 3 mặc định, một `main.dart` lớn, detail bằng dialog, setup kỹ thuật |
| Prototype HTML | Hoàn tất | `prototypes/macos`; có ready, locked, setup, offline, denied và empty |
| So sánh thư viện | Hoàn tất | `docs/macos-ui-library-research.md` |
| Spike `macos_ui` và Forui | Hoàn tất | Cùng model/list/detail; analyze, widget test và debug build macOS pass |
| Chọn thư viện | Hoàn tất | Forui được chọn cho production |
| Nâng toolchain + Forui 0.26.0 | Hoàn tất | Flutter 3.47.2 / Dart 3.13.2; `forui: 0.26.0` pin chính xác |
| Gỡ `macos_ui` khỏi production | Hoàn tất | `flutter pub deps` không còn `macos_ui`/`macos_window_utils`; spike archive tại `apps/desktop-flutter/spikes/macos_ui/` |
| Migration production | Hoàn tất phần Dart | `lib/main.dart` chỉ còn `runApp`; app nằm ở `lib/app`, `lib/core`, `lib/features`, `lib/ui` |
| Nghiệm thu trên Mac thật | Chưa | Phiên triển khai chạy trên Linux; xem "Chưa kiểm chứng" |

Spike ban đầu pin Forui 0.21.3 vì máy đó dùng Flutter 3.41.4. Đã nâng xong:
production và spike hiện dùng Forui `0.26.0` trên Flutter 3.47.2. Forui vẫn ở
version `0.x`, nên version được pin chính xác và mỗi lần nâng phải review
changelog; danh sách breaking change đã xử lý nằm trong
[forui-migration-decisions.md](forui-migration-decisions.md).

## Mục tiêu sản phẩm

Đưa KeyLease từ giao diện thao tác kỹ thuật thành ứng dụng dễ bắt đầu, dễ tìm
thông tin và dùng tốt bằng chuột, bàn phím hoặc cảm ứng. Luồng ưu tiên:

```text
Mở app → kết nối/khôi phục phiên → mở khóa → tìm entry
        → copy hoặc chỉnh sửa → khóa
```

Mục tiêu đa nền tảng là đồng bộ ngôn ngữ sản phẩm, component và trạng thái;
navigation và interaction thích ứng theo thiết bị:

| Form factor | Cấu trúc |
| --- | --- |
| Desktop | Sidebar → danh sách → detail; pane thay đổi kích thước; hover và keyboard |
| Tablet | Sidebar/rail thu gọn; list/detail khi đủ rộng; touch targets lớn hơn |
| Phone | Navigation compact; list → detail route; sheet cho tác vụ phụ |

## Kiến trúc UI mục tiêu

```text
lib/
├── app/
│   ├── keylease_app.dart
│   ├── app_theme.dart             # FTheme light/dark, touch/desktop
│   └── adaptive_shell.dart        # chọn shell theo kích thước và input
├── core/
│   ├── rpc/
│   ├── models/
│   ├── state/
│   └── platform/                  # interface cho native adapters
├── features/
│   ├── onboarding/
│   ├── vault/
│   ├── connections/
│   ├── approvals/
│   ├── activity/
│   └── settings/
└── ui/
    ├── tokens/
    └── components/                # component nghiệp vụ trên Forui
```

State/view model, validation, permission semantics và RPC dùng chung. Shell,
navigation và một số interaction thay đổi theo form factor. Widget nghiệp vụ
như `SecretField`, `EntryRow`, `RequestSummary` và `ConnectionHealth` xây trên
Forui và token của KeyLease.

## Nguyên tắc thiết kế

- Một hierarchy rõ ràng; không dùng card cho mọi nội dung.
- Desktop dùng list/detail thường trực; không dùng dialog để xem metadata entry.
- Search phản hồi khi gõ, debounce RPC và bỏ kết quả của truy vấn cũ.
- Copy, reveal, TOTP và edit đặt cạnh field liên quan; secret mặc định bị che.
- Tách rõ checking, setup required, service unavailable, locked, ready,
  permission denied và empty.
- Lỗi viết bằng ngôn ngữ người dùng, có hành động khắc phục; JSON kỹ thuật chỉ
  nằm trong phần details hoặc diagnostics đã redaction.
- Light/dark và màu ngữ nghĩa đi qua `FTheme`; không hard-code theme theo màn hình.
- Theme desktop và touch dùng cùng brand nhưng khác density, padding và target size.
- macOS có Cmd+F, Cmd+N, Cmd+, menu hệ thống, context menu và focus rõ ràng.
- Android/iOS có touch targets, back behavior, keyboard avoidance và navigation
  phù hợp màn hình nhỏ.
- Backend tiếp tục là ranh giới quyết định capability; UI không nới quyền để
  làm flow ngắn hơn.

## Kế hoạch triển khai

Ước lượng là ngày công tập trung cho macOS production và nền móng adaptive,
chưa bao gồm hoàn thiện/phát hành riêng Android, iOS và Windows. Tổng khoảng
16–25 ngày công nếu hợp đồng IPC hiện tại đủ cho UI đã thiết kế.

### Giai đoạn 0 — Khóa baseline Forui (1–2 ngày)

- Chuyển toolchain development/CI sang Flutter 3.47.2 theo runbook của repo.
- Nâng spike từ Forui 0.21.3 lên 0.26.x; chạy `dart fix` khi changelog yêu cầu.
- Chốt `FTheme` light/dark, desktop/touch và token KeyLease.
- So spike với prototype ở 800×600 và 1280×800.
- Tách hoặc archive spike `macos_ui`; loại `macos_ui` và native plugins của nó
  khỏi dependency graph production trước khi merge migration.

Hoàn tất khi Forui spike mới pass analyze, widget test và debug build; production
entry point cũ vẫn build; không còn dependency native chỉ phục vụ spike đối chứng.

**Trạng thái: hoàn tất, trừ debug build macOS.** Flutter 3.47.2/Dart 3.13.2;
`forui: 0.26.0`; `material_ui: 1.1.1`; `macos_ui` đã bị gỡ; spike archive ngoài
`lib/`; `flutter analyze` sạch, `flutter test` pass, `flutter build bundle`
compile toàn bộ app. `flutter build macos --debug` chưa chạy vì không có host macOS.

### Giai đoạn 1 — Foundation và app states (3–5 ngày)

- Tách RPC, typed models và state khỏi `main.dart`.
- Tạo `KeyLeaseApp`, `FTheme`, tokens và adaptive shell.
- Tạo desktop shell bằng `FScaffold`/`FSidebar`; split pane là component custom
  có min/max width, lưu kích thước và breakpoint.
- Tạo phone/tablet shell tối thiểu để chứng minh cùng feature state tái sử dụng.
- Xây state router: checking, setup, offline, locked, ready, denied và empty.
- Settings dùng draft độc lập; Save/Cancel đúng nghĩa; không lưu secret.

Hoàn tất khi trạng thái mở app không còn bị đồng nhất sai thành “locked”,
không overflow ở breakpoint mục tiêu và cùng state model render được trên
desktop lẫn phone fixture.

**Trạng thái: hoàn tất.** `AppPhase` tách 6 trạng thái, `VaultListState` tách
empty/search-empty; `SplitPane` có min/max, lưu độ rộng và điều khiển được bằng
bàn phím; shell desktop/rail/compact chọn theo breakpoint; Settings dùng draft.
Test: `test/app_state_test.dart`, `test/adaptive_shell_test.dart`,
`test/vault_flow_test.dart`.

### Giai đoạn 2 — Vault cốt lõi (4–6 ngày)

- Chuyển Vault sang list/detail; cửa sổ hẹp dùng list → detail.
- Search debounce, cancel/ignore response cũ và hiển thị loading tại đúng vùng.
- Xây `EntryRow`, `SecretField`, website, TOTP, notes và metadata mở rộng.
- Copy/reveal theo yêu cầu; feedback rõ; reset nội dung nhạy cảm khi lock/sleep.
- Tạo/edit/delete với validation, dirty state và retry không mất bản nháp.
- Empty/search-empty state có bước tiếp theo phù hợp.

Hoàn tất khi tìm → chọn → copy làm được bằng chuột và bàn phím; CRUD hoạt động
với IPC thật; RPC lỗi không làm mất draft hoặc lộ secret.

**Trạng thái: hoàn tất ở mức fixture.** Search debounce 220 ms và bỏ response cũ
theo sequence; reveal/copy lấy dữ liệu theo yêu cầu qua adapter native; draft
sống sót qua save lỗi. CRUD với **IPC thật** chưa chạy vì phiên này không có
daemon đang chạy — xem "Chưa kiểm chứng".

### Giai đoạn 3 — Onboarding và màn hình phụ (3–5 ngày)

- Onboarding chẩn đoán daemon, client token và capability bằng từng trạng thái.
- Connections hiển thị provider, account, health, resources và cách sửa lỗi.
- Approvals trình bày client, action, resource, scope, reason và expiry; confirm
  vẫn gắn với exact request digest.
- Activity có filter, thời gian dễ đọc và technical details đã redaction.
- Kiểm tra fields/IPC còn thiếu cho favorite, recent ordering, display name và
  reason; bỏ khỏi UI hoặc bổ sung contract có chủ đích, không giả dữ liệu.

Hoàn tất khi người dùng luôn biết bước tiếp theo và mọi thao tác nhạy cảm vẫn
qua policy/backend hiện tại.

**Trạng thái: hoàn tất.** Mỗi phase có màn hình riêng kèm hành động kế tiếp;
Connections hiển thị health + `health_reason` + cách sửa; Approvals dùng
`risk`/`semantic_summary` và ràng buộc quyết định vào đúng digest, từ chối
request đã hết hạn hoặc đã đổi; Activity có filter và thời gian dễ đọc. Các field
không có trong contract đã bị bỏ khỏi UI, ghi trong
[forui-migration-decisions.md](forui-migration-decisions.md).

### Giai đoạn 4 — Hoàn thiện macOS (3–5 ngày)

- Nối menu native, shortcuts, context menu, window state và restore kích thước.
- Hoàn thiện hover, focus traversal, pointer cursor và pane resizing.
- Rà soát typography, icon, contrast, light/dark và text scaling.
- Kiểm thử VoiceOver, clipboard timeout, file access, OAuth browser flow,
  sleep/screen lock và sandbox trên Mac thật.
- Đo với dữ liệu lớn và sửa bottleneck UI/RPC có bằng chứng.

Hoàn tất khi bản release macOS vượt checklist nghiệm thu và không còn lỗi chặn
luồng mở khóa, tìm, copy, edit hoặc lock.

**Trạng thái: một phần.** Đã làm: menu native + window autosave trong
`MainFlutterWindow.swift` (kèm phát hiện AppKit nuốt ⌘F/⌘,), shortcuts, focus,
hover cursor, pane resizing bằng chuột và bàn phím, typography/token light-dark,
kiểm tra text scaling 1.4×. **Chưa làm/chưa kiểm chứng:** build và chạy trên Mac
thật, VoiceOver, clipboard/sleep/screen-lock/file-access thực tế, sandbox,
context menu, và đo hiệu năng với 1.000 entry.

### Giai đoạn 5 — Xác nhận nền móng đa nền tảng (2 ngày)

- Build Forui shell trên Android, iOS và Windows bằng fixture, chưa nối secret thật.
- Xác minh touch/desktop theme, navigation breakpoint và feature contracts.
- Ghi backlog riêng cho native adapter và release acceptance của từng platform.

Hoàn tất khi cùng model và component nghiệp vụ compile trên các target được hỗ
trợ; các khác biệt platform được ghi thành adapter hoặc shell task, không tạo
fork của business logic.

**Trạng thái: một phần.** Cùng một cây widget render đúng cho macOS, Windows,
Android và iPad trong widget test (`cross-platform shell` trong
`test/adaptive_shell_test.dart`), không có fork business logic. **Chưa làm:**
repo chưa có thư mục runner `android/`, `ios/`, `windows/`, nên chưa có build
thật cho các target đó; đây là backlog riêng cùng với native adapter tương ứng.

## Checklist nghiệm thu macOS

Cập nhật 2026-09-07. `[x]` = đã kiểm chứng bằng lệnh chạy thật trên máy triển
khai (Linux, Flutter 3.47.2). `[~]` = đã triển khai nhưng chỉ kiểm chứng ở mức
analyze/widget test. `[ ]` = chưa đạt, cần Mac thật hoặc daemon thật.

- [x] Production dùng Forui 0.26.x đã pin với Flutter 3.47.2; lockfile được review.
- [x] `macos_ui` không còn trong dependency graph production.
- [~] `flutter analyze` và widget tests pass (57 test). Debug/release build macOS
      **chưa chạy**: không có host macOS. `flutter build bundle` compile được
      toàn bộ app.
- [x] Phân biệt đúng setup, offline, locked, denied, ready và empty.
- [~] Không overflow ở 800×600 và 1280×800; đã test light/dark và text scaling
      1.4×. Retina và text scaling ở mức hệ điều hành chưa test trên Mac thật.
- [ ] Tìm và copy entry có sẵn trong ≤10 giây sau hướng dẫn ban đầu — cần đo với
      người dùng thật.
- [ ] Với 1.000 entry giả, search-to-results p95 ≤500 ms — cần daemon thật.
- [~] Unlock, search, chọn entry, copy, edit và lock dùng được bằng keyboard;
      focus luôn thấy được. **VoiceOver chưa test** — cần Mac thật.
- [x] Response cũ không ghi đè màn hình mới; lỗi không mất draft; busy state chỉ
      khóa action liên quan (`BusyRegistry` theo key).
- [~] Secret mặc định che; reveal theo yêu cầu; lock/sleep/screen lock xóa nội
      dung nhạy cảm. Cơ chế clipboard có điều kiện giữ nguyên trong Swift, nhưng
      chỉ được kiểm chứng qua adapter giả.
- [x] Approval hết hạn hoặc đã xử lý không thể quyết định lại từ state cũ.
- [ ] Kiểm thử native clipboard, security-scoped file, window và sleep trên Mac thật.

### Chưa kiểm chứng trong phiên triển khai này

Phiên chạy trên Linux (`ruan-dev`), không có macOS host, không có daemon
KeyLease đang chạy. Những mục sau **chưa được chạy thật**, không suy diễn:

1. `flutter build macos --debug` và `--release`.
2. Mã Swift mới trong `MainFlutterWindow.swift` (menu native, window autosave)
   chưa được compile.
3. VoiceOver, Retina, text scaling ở mức hệ điều hành.
4. Clipboard có điều kiện, security-scoped file access, sleep/screen lock,
   sandbox và OAuth browser flow trên máy thật.
5. CRUD và search với IPC thật; đo p95 với 1.000 entry.
6. Build Android, iOS và Windows: repo chưa có thư mục runner cho các target đó.

## Việc còn lại

Các bước 1–4 của thứ tự cũ đã xong. Còn lại, theo thứ tự:

1. Trên một Mac có Xcode: `flutter build macos --debug` rồi `--release`, sửa mọi
   lỗi compile Swift phát sinh từ menu native và window autosave.
2. Chạy `keylease serve --start-locked`, đăng ký client, rồi kiểm chứng CRUD,
   search, copy, TOTP, approvals và Activity với IPC thật.
3. Nghiệm thu macOS: VoiceOver, clipboard có điều kiện, security-scoped file,
   sleep/screen lock, sandbox, Retina và text scaling.
4. Đo p95 search với 1.000 entry giả; nếu không đạt, xác định UI hay backend.
5. Thêm runner `android/`, `ios/`, `windows/` và build fixture trên từng target;
   ghi backlog native adapter riêng cho mỗi platform.
6. Nếu muốn Favorites, recent ordering hoặc tên client dễ đọc: bổ sung contract
   IPC có test trước, không thêm dữ liệu giả vào UI.

Hoãn animation trang trí, dashboard mới, AI feature và đổi thương hiệu cho đến
khi luồng chính và acceptance macOS hoàn tất.
