# KeyLease macOS — HTML prototype 01

Prototype thiết kế tương tác, dùng dữ liệu giả hoàn toàn. Không gọi daemon,
đọc token, đăng ký client hoặc thay đổi app Flutter.

## Mở prototype

Mở trực tiếp `index.html` bằng trình duyệt, hoặc từ repo root chạy:

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory prototypes/macos
```

Sau đó mở http://127.0.0.1:4173. Không cần npm install, build hay CDN.

## Cách review

1. Vault: chọn entry, tìm theo tên/tài khoản/URL, thử Favorites và groups.
2. Xem mật khẩu mẫu, copy, mở TOTP; tạo/sửa item và thử hủy bản nháp.
3. Connections: kiểm tra, ngắt/kết nối lại tài khoản mẫu.
4. Approvals: review rồi approve/deny; xem kết quả trong Activity.
5. Chọn Preview để thử locked, onboarding, offline, denied và empty.
6. Mật khẩu mở khóa mẫu: `demo`. Không nhập mật khẩu thật.
7. Đổi light/dark bằng nút trên thanh review hoặc Settings.
8. Thu hẹp cửa sổ: dưới 920 px, chọn item mở detail và dùng Items để quay lại.
9. Ở cửa sổ rộng, kéo đường phân cách để đổi độ rộng sidebar/list; có thể focus
   separator và dùng ArrowLeft/ArrowRight. Cmd+F, Cmd+N, Cmd+, và ↑/↓ trong list.

Reset hoặc reload khôi phục dữ liệu. Mọi chỉnh sửa chỉ nằm trong RAM.
Clipboard có ghi giá trị **giả** khi nhấn Copy; nếu trình duyệt từ chối thì hiện
ô cho copy thủ công. Prototype không mô phỏng việc xóa clipboard có điều kiện
của macOS; không dùng nó để giữ credential thật. Reveal tự che sau 15 giây.
TOTP là mã cố định có nhãn demo, không phải mã được tính từ secret.

## Phạm vi chính xác

- Có thể đánh giá: bố cục, mật độ, hierarchy, focus, trạng thái, copy, modal,
  điều hướng và các thao tác với dữ liệu mẫu.
- Chưa thể kết luận: cảm giác native, VoiceOver trong Flutter, traffic-light
  behavior, menu hệ thống, sandbox, IPC latency, clipboard/sleep protection.
- Traffic lights là hình tham chiếu không tương tác; đây là trang HTML, không
  có quyền thu nhỏ/đóng cửa sổ ứng dụng native.
- Setup/reconnect/check connection/approval đều là mô phỏng và được ghi nhận
  trong Activity mẫu. Không có OAuth hoặc yêu cầu quyền thật.
- History là fixture minh họa. “Recently used” là thứ tự fixture ban đầu.
- Favorites, recent ordering, tên client dễ đọc và lý do approval là đề xuất
  UX cần kiểm tra model/IPC trước khi port; không khẳng định backend đã có đủ.
- Group CRUD, phục hồi revision, enroll/revoke resource và bộ lọc Activity
  đầy đủ chưa được mô phỏng. Những tính năng này vẫn thuộc backlog app gốc.
- Browser có thể ưu tiên phím tắt của chính nó. Kiểm chứng native menu cần
  một Flutter spike riêng sau khi thống nhất thiết kế.

## Cấu trúc và chuyển sang Flutter

- `styles.css`: token light/dark và component styles; system font stack.
- `index.html`: khung cửa sổ và thanh điều khiển review tách khỏi app.
- `app.js`: icon SVG chức năng, fixtures, các trạng thái và tương tác.
- `verify.cjs`: kiểm thử headless tùy chọn bằng Playwright đã cài trên máy.

Chiều rộng baseline: sidebar 214 px, list 306 px; compact 190/263 px;
toolbar 61 px; row 65 px; control thường 30–36 px. Font nội dung desktop
13–14 px, metadata 11–12 px, tên item 25 px. Đây là token cho desktop có
mật độ tương đối cao, cần kiểm tra text scaling/VoiceOver khi triển khai native.

| Prototype | Ứng viên triển khai Flutter |
| --- | --- |
| Sidebar và toolbar | Forui: `FScaffold`, `FSidebar`, `FHeader` và action phù hợp |
| Split view | `LayoutBuilder` + pane custom, giữ selection và chuyển list/detail theo breakpoint |
| Search, button, field, dialog | Forui controls; bọc thành component semantic của KeyLease |
| EntryRow, SecretField, RequestSummary | Widget custom dùng Forui theme và design token của KeyLease |
| Menu, cửa sổ, clipboard, file access | Adapter native hiện có, kiểm tra độc lập trên từng platform |
| Dữ liệu và trạng thái | Typed view models gọi IPC hiện tại; không port fixture handlers |

Không port CSS thành widget theo từng pixel một cách máy móc. Lấy structure,
token, hierarchy và interaction làm hợp đồng; giữ hành vi native quan trọng qua
platform adapter dù component system dùng chung là Forui.

## Kiểm thử tùy chọn

`verify.cjs` dùng Playwright có sẵn qua `require('playwright')`. Nếu cài ở nơi
khác, đặt `PLAYWRIGHT_MODULE` thành đường dẫn tuyệt đối tới module đó, rồi:

```sh
node prototypes/macos/verify.cjs
```

Server cần chạy trước; `PROTOTYPE_URL` cho phép đổi địa chỉ. Test tạo screenshots
trong thư mục tạm, in đường dẫn ở cuối. Không cần dependency để dùng prototype.

Kết quả ngày 2026-09-07: 17 nhóm kiểm tra pass trên Chromium headless
145.0.7632.6 / Playwright 1.58.2; không có JavaScript exception. Đã kiểm tra
search, keyboard, copy, bản nháp, CRUD, approvals, connections, Activity,
Settings và các trạng thái Preview. Không có horizontal page overflow tại
390, 800, 1280 px trong ma trận kiểm tra; 800×600 chuyển list/detail đúng.
Đã xem ảnh render light, dark và 800×600. Chưa kiểm tra Safari, VoiceOver,
text zoom 200% hoặc app macOS native; không coi đây là chứng nhận accessibility.

Xem [research và quyết định UI](../../docs/macos-ui-library-research.md).
