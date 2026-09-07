# UI cho KeyLease macOS: thư viện và prototype

## Kết luận

Thiết kế custom theo macOS đã được review bằng HTML/CSS. Sau khi so sánh hai
Flutter spike, ngày 2026-09-07 dự án chốt **Forui làm UI library production**
cho một codebase đa nền tảng. `macos_ui` được giữ làm mẫu đối chiếu về desktop
shell, không phải hướng triển khai tiếp theo.

Prototype đầu tiên nằm tại [`prototypes/macos`](../prototypes/macos/README.md).
Đây là bản thiết kế có tương tác, không phải bản build web của `macos_ui`.

**Cập nhật 2026-09-07 (sau migration):** đã nâng toolchain lên Flutter 3.47.2 và
Forui `0.26.0`, gỡ `macos_ui` khỏi production, và triển khai app production trên
Forui. Quyết định phát sinh: [forui-migration-decisions.md](forui-migration-decisions.md).
Còn lại là nghiệm thu trên macOS thật.

Hai Flutter spike đã được thêm tại
[`apps/desktop-flutter/lib/ui_spikes`](../apps/desktop-flutter/UI_SPIKES.md):
`macos_ui` 2.2.2 và Forui 0.21.3 dùng cùng model/list/detail. Cả hai đã qua
analyzer và debug build macOS với runner hiện tại. Xem tài liệu spike để biết
toolchain, giới hạn kiểm tra và lý do version Forui được pin thấp hơn bản mới nhất.

## Research trả lời quyết định nào?

Không chỉ tìm bộ button đẹp hơn Material 3. Cần một khung desktop có sidebar,
toolbar, list/detail, bàn phím, focus, window behavior và trạng thái nghiệp vụ
phù hợp với password manager. Thư viện chỉ giải quyết một phần những việc này.

Nguồn dưới đây được truy cập ngày 2026-09-07. Không dùng số star/download làm
bằng chứng rằng một thư viện phù hợp hoặc đã đạt chất lượng production.

## So sánh cho Flutter

| Lựa chọn | Có gì từ tài liệu chính thức/tác giả | Đánh giá cho KeyLease (suy luận) |
| --- | --- | --- |
| **macos_ui** | MacosWindow, Sidebar, ToolBar, ResizablePane, controls, dialog/sheet; tích hợp macos_window_utils | Tham chiếu tốt cho app chỉ tập trung macOS, nhưng không được chọn vì làm tăng số UI implementation cho lộ trình đa nền tảng |
| **shadcn_ui** | Các widget Flutter theo shadcn; theming và cách tích hợp với app hiện có | Hợp với giao diện trung tính đa nền tảng; vẫn phải làm khung và hành vi Mac |
| **shadcn_flutter** | Một dự án riêng, cung cấp hệ component theo hướng shadcn cho Flutter | Lựa chọn khác để đánh giá nếu cần catalog rộng; không trộn lẫn với shadcn_ui hoặc coi là cùng package |
| **Forui** | Flutter UI library lấy cảm hứng từ shadcn; package khai báo Android, iOS, Linux, macOS, web và Windows; có touch/desktop theme cùng platform variants | Có thể làm design system đồng nhất đa nền tảng; shell/navigation vẫn phải thích ứng phone, tablet và desktop |
| **fluent_ui** | Triển khai ngôn ngữ giao diện Windows trong Flutter | Có desktop controls nhưng định hướng thị giác khác mục tiêu Mac |
| **Cupertino** | Widget theo thiết kế iOS | Chỉ đổi Material sang Cupertino không tạo ra macOS shell đúng nghĩa |
| **Custom trên Flutter widgets** | Tự xây layout, trạng thái và component | Toàn quyền thiết kế; tự chịu chi phí text editing, focus, semantics và accessibility; dùng có chọn lọc |

Nguồn: [macos_ui](https://pub.dev/packages/macos_ui),
[shadcn_ui](https://pub.dev/packages/shadcn_ui),
[shadcn_flutter](https://pub.dev/documentation/shadcn_flutter/latest/index.html),
[Forui](https://forui.dev/docs),
[fluent_ui](https://pub.dev/packages/fluent_ui),
[Flutter Cupertino](https://docs.flutter.dev/ui/widgets/cupertino).

`macos_ui` là community package, không phải bộ AppKit controls do Apple cung cấp.
Trang package hiện hiển thị 2.2.2, yêu cầu Flutter stable phù hợp và ghi chú giới
hạn popup trong cửa sổ. Repo đang có Swift security adapter; khả năng cùng tồn
tại với window plugin cần kiểm chứng thực tế. Không sao chép nguyên runner từ
example để tránh làm mất xử lý clipboard, sleep và security-scoped file access.
[Nguồn package và integration](https://github.com/macosui/macos_ui).

Forui tự định vị là platform-agnostic và touch-first. Điều đó hỗ trợ một visual
language chung, nhưng không có nghĩa cùng một cây widget sẽ có UX tối ưu trên
mọi thiết bị. Ví dụ, desktop cần sidebar/list-detail, hover và keyboard; phone
cần navigation compact và list-to-detail. Forui cung cấp controls/theme cho cả
hai nhóm, còn responsive information architecture thuộc trách nhiệm của app.
[Nguồn package](https://pub.dev/packages/forui) và
[getting started](https://forui.dev/docs/getting-started).

## So sánh cho HTML prototype

| Lựa chọn | Điểm mạnh có nguồn | Đánh giá và lựa chọn |
| --- | --- | --- |
| **Radix Primitives + CSS custom** | Components không kèm style, có xử lý focus/keyboard và ARIA patterns | Ưu tiên nếu mở rộng prototype thành React app nhiều tương tác phức tạp |
| **React Aria + CSS custom** | Components/hooks tập trung accessibility, có thể tùy biến style | Ứng viên tốt cho collections, selection và tương tác keyboard cần kiểm tra kỹ |
| **shadcn/ui** | Cung cấp source component có thể sửa, composition và theme | Khởi tạo nhanh; vẫn phải thiết kế lại shell để tránh giao diện dashboard web thông thường |
| **HTML semantic + CSS/JS custom** | Browser có button, input, select, dialog; không cần runtime UI bên ngoài | Chọn cho prototype 01: mở trực tiếp được, dễ sửa token và không khóa thiết kế vào React |

Nguồn: [Radix introduction](https://www.radix-ui.com/primitives/docs/overview/introduction),
[Radix styling](https://www.radix-ui.com/primitives/docs/guides/styling),
[React Aria](https://react-aria.adobe.com/),
[shadcn/ui](https://ui.shadcn.com/docs).

Custom ở đây là **visual language và composition riêng**, không có nghĩa phải
tự viết tất cả control hoặc bỏ semantics. Prototype dùng button/input/select/
dialog thật, có label, focus và xử lý bản nháp. Nếu mở rộng thành sản phẩm web,
chuyển các tương tác phức tạp sang primitive đã được kiểm thử; HTML hiện tại
không phải thư viện accessibility được chứng nhận.

## Bằng chứng và giới hạn

| Nhận định | Loại bằng chứng | Tin cậy | Hệ quả |
| --- | --- | --- | --- |
| macos_ui có shell, toolbar và pane co giãn | Official/Source: tài liệu package | Cao | Có cơ sở để chọn làm ứng viên spike |
| Cupertino hướng iOS, Fluent hướng Windows | Official: tài liệu Flutter/package | Cao | Không chọn chỉ vì đều là “desktop/Apple UI” |
| Radix không áp đặt style; shadcn cho sửa source | Official: tài liệu hai dự án | Cao | Có thể custom thay vì nhận theme mặc định |
| Forui là baseline phù hợp hơn cho KeyLease | Quyết định sau research + hai spike dùng chung fixture | Trung bình-cao | Một component system cho mọi target; vẫn cần responsive shell và native adapter theo nền tảng |
| Prototype ánh xạ được sang Flutter | Inference + bảng mapping component | Trung bình | Cần native spike trước khi hứa pixel fidelity |
| HTML không có dependency runtime bên ngoài | Source: index.html/styles.css/app.js | Cao | Dùng offline được, không tải font/CDN hoặc gửi dữ liệu |

## Những việc phải xác minh khi triển khai app

1. ~~Dùng Flutter 3.47.2 theo release baseline, nâng Forui từ spike 0.21.3 lên
   0.26.x, xử lý migration rồi pin chính xác phiên bản đã kiểm chứng.~~ Đã xong:
   `forui: 0.26.0` trên Flutter 3.47.2.
2. Giữ runner và native adapter hiện có; kiểm thử native file access, menu,
   copy timeout, sleep/screen lock trong lúc RPC đang chạy.
3. So cùng mẫu ở 800×600, 1280×800, light/dark, resize và text scaling.
4. Dùng keyboard và VoiceOver trên Mac thật. DOM semantics của HTML không chứng
   minh Flutter semantics hoặc behavior của native window.
5. Kiểm tra fields/IPC cho Favorites, recent ordering, display name, reason và
   resource label. Đây là UX đề xuất, không tạo API giả hoặc nới quyền để khớp UI.
6. Dùng cùng fixture/contract để kiểm tra shell desktop, tablet và phone; không
   coi việc Forui hỗ trợ nhiều target là bằng chứng UX đã tự động thích ứng.

## Thiết kế đã chọn cho prototype 01

Sidebar màu xám lạnh; bề mặt nội dung sáng; accent xanh cho selection và hành
động chính; system font; toolbar gọn; list/detail thay dialog xem item; copy ở
từng field; approval đọc được bằng ngôn ngữ người dùng; trạng thái mất dịch vụ
tách khỏi locked. Light/dark dùng cùng bộ token ngữ nghĩa.

Định hướng dựa trên [Apple macOS HIG](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos/).
Prototype không cố mô phỏng hiệu ứng Liquid Glass hoặc tính năng của một bản
macOS mới nhất khi repo còn cần hỗ trợ các phiên bản cũ.
