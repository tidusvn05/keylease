# Kế hoạch cải thiện UI/UX KeyLease

Ngày cập nhật: 2026-09-07. Trạng thái: **đã chốt Forui; prototype và spike hoàn tất**.

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
| Migration production | Chưa bắt đầu | `lib/main.dart` vẫn là app Material 3 hiện tại |

Spike đang pin Forui 0.21.3 vì máy thực hiện dùng Flutter 3.41.4. Toolchain
release của repo là Flutter 3.47.2; cổng đầu tiên của migration là nâng lên
Forui 0.26.x tương thích, chạy migration cần thiết và xác minh lại. Forui đang
ở version `0.x`, vì vậy production phải pin version và review changelog trước
mỗi lần nâng.

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

### Giai đoạn 2 — Vault cốt lõi (4–6 ngày)

- Chuyển Vault sang list/detail; cửa sổ hẹp dùng list → detail.
- Search debounce, cancel/ignore response cũ và hiển thị loading tại đúng vùng.
- Xây `EntryRow`, `SecretField`, website, TOTP, notes và metadata mở rộng.
- Copy/reveal theo yêu cầu; feedback rõ; reset nội dung nhạy cảm khi lock/sleep.
- Tạo/edit/delete với validation, dirty state và retry không mất bản nháp.
- Empty/search-empty state có bước tiếp theo phù hợp.

Hoàn tất khi tìm → chọn → copy làm được bằng chuột và bàn phím; CRUD hoạt động
với IPC thật; RPC lỗi không làm mất draft hoặc lộ secret.

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

### Giai đoạn 4 — Hoàn thiện macOS (3–5 ngày)

- Nối menu native, shortcuts, context menu, window state và restore kích thước.
- Hoàn thiện hover, focus traversal, pointer cursor và pane resizing.
- Rà soát typography, icon, contrast, light/dark và text scaling.
- Kiểm thử VoiceOver, clipboard timeout, file access, OAuth browser flow,
  sleep/screen lock và sandbox trên Mac thật.
- Đo với dữ liệu lớn và sửa bottleneck UI/RPC có bằng chứng.

Hoàn tất khi bản release macOS vượt checklist nghiệm thu và không còn lỗi chặn
luồng mở khóa, tìm, copy, edit hoặc lock.

### Giai đoạn 5 — Xác nhận nền móng đa nền tảng (2 ngày)

- Build Forui shell trên Android, iOS và Windows bằng fixture, chưa nối secret thật.
- Xác minh touch/desktop theme, navigation breakpoint và feature contracts.
- Ghi backlog riêng cho native adapter và release acceptance của từng platform.

Hoàn tất khi cùng model và component nghiệp vụ compile trên các target được hỗ
trợ; các khác biệt platform được ghi thành adapter hoặc shell task, không tạo
fork của business logic.

## Checklist nghiệm thu macOS

- [ ] Production dùng Forui 0.26.x đã pin với Flutter 3.47.2; lockfile được review.
- [ ] `macos_ui` không còn trong dependency graph production.
- [ ] `flutter analyze`, widget tests và debug/release build pass.
- [ ] Phân biệt đúng setup, offline, locked, denied, ready và empty.
- [ ] Không overflow ở 800×600 và 1280×800; test Retina, light/dark, text scaling.
- [ ] Tìm và copy entry có sẵn trong ≤10 giây sau hướng dẫn ban đầu.
- [ ] Với 1.000 entry giả, search-to-results p95 ≤500 ms gồm debounce và RPC
      trên máy nghiệm thu; xác định UI/backend nếu không đạt.
- [ ] Unlock, search, chọn entry, copy, edit và lock dùng được bằng keyboard;
      focus luôn thấy được và VoiceOver đọc đúng nhãn/trạng thái.
- [ ] Response cũ không ghi đè màn hình mới; lỗi không mất draft; busy state
      chỉ khóa action liên quan.
- [ ] Secret mặc định che; reveal theo yêu cầu; lock/sleep/screen lock xóa nội
      dung nhạy cảm; clipboard giữ cơ chế xóa có điều kiện hiện tại.
- [ ] Approval hết hạn hoặc đã xử lý không thể quyết định lại từ state cũ.
- [ ] Kiểm thử native clipboard, security-scoped file, window và sleep trên Mac thật.

## Thứ tự thực hiện ngay

1. Nâng toolchain và Forui, khóa theme/tokens.
2. Tách state/RPC khỏi `main.dart` và dựng adaptive shell production.
3. Chuyển hoàn chỉnh luồng Vault.
4. Chuyển onboarding, Connections, Approvals, Activity và Settings.
5. Hoàn thiện macOS native behavior và acceptance.
6. Build fixture trên Android, iOS và Windows để xác nhận kiến trúc dùng chung.

Hoãn animation trang trí, dashboard mới, AI feature và đổi thương hiệu cho đến
khi luồng chính và acceptance macOS hoàn tất.
