# Prompt triển khai kế hoạch Forui

Sao chép prompt dưới đây cho coding agent trên máy triển khai:

```text
Bạn đang làm việc trong repository KeyLease. Hãy triển khai kế hoạch cải thiện
UI/UX bằng Forui, không chỉ phân tích hoặc viết thêm kế hoạch.

Trước khi sửa code, hãy đọc đầy đủ:

- docs/macos-ui-ux-improvement-plan.md — kế hoạch và acceptance criteria chính.
- docs/macos-ui-library-research.md — quyết định thư viện và trade-off.
- apps/desktop-flutter/UI_SPIKES.md — kết quả hai spike và giới hạn toolchain.
- prototypes/macos/README.md, sau đó mở prototypes/macos/index.html — visual và
  interaction reference.
- apps/desktop-flutter/lib/ui_spikes/forui_spike.dart cùng shared model/widgets.
- Production app hiện tại tại apps/desktop-flutter/lib/main.dart và các tài liệu
  build/release liên quan trong repo.

Quyết định đã chốt, không mở lại lựa chọn thư viện nếu không gặp blocker có bằng
chứng:

- Forui là component library/design-system baseline cho production.
- Dùng một codebase Flutter cho macOS, Windows, Android và iOS.
- macOS là target triển khai và nghiệm thu đầu tiên.
- UI/navigation thích ứng theo form factor; không ép desktop shell lên mobile.
- Không dùng macos_ui trong production. Spike macos_ui chỉ là đối chứng.
- Giữ Rust daemon, IPC, policy và security boundary hiện tại.
- Giữ native adapter cho menu/window, clipboard, file access, sleep/screen lock
  và OAuth flow. Không thay chúng bằng fixture hoặc logic UI.

Hãy làm theo các phase trong plan, bắt đầu từ Phase 0 và tiếp tục qua các phase
có thể hoàn thành an toàn trong phiên làm việc. Không dừng sau khi dựng skeleton
nếu vẫn có thể triển khai và kiểm chứng luồng tiếp theo.

Yêu cầu Phase 0:

1. Kiểm tra Flutter/Dart thực tế trên máy và đối chiếu release baseline Flutter
   3.47.2 của repo.
2. Nâng Forui spike từ 0.21.3 lên dòng 0.26.x tương thích với toolchain đã chốt;
   đọc migration/changelog tương ứng và pin version chính xác.
3. Chạy analyze, widget tests và macOS debug build trước khi chuyển production.
4. Tạo FTheme light/dark, desktop/touch và design tokens KeyLease.
5. Loại macos_ui cùng các plugin chỉ do nó kéo vào khỏi production dependency
   graph; có thể giữ source spike được cô lập nếu không ảnh hưởng build.

Yêu cầu kiến trúc và triển khai:

- Tách RPC, typed models, app state và platform adapters khỏi main.dart trước khi
  chia feature UI. Không viết lại daemon hoặc đổi IPC ngoài nhu cầu UI đã chứng minh.
- Tạo KeyLeaseApp, adaptive shell và feature modules theo cấu trúc trong plan.
- Desktop: sidebar + list/detail + pane co giãn + keyboard/hover/focus.
- Phone: navigation compact và list → detail route.
- Tablet: rail/sidebar thu gọn và list/detail khi đủ rộng.
- Các component nghiệp vụ như EntryRow, SecretField, RequestSummary và
  ConnectionHealth dùng chung model/contract, xây trên Forui và token KeyLease.
- Triển khai state riêng cho checking, setup required, offline, locked, ready,
  permission denied và empty; không gom các lỗi thành locked.
- Secret mặc định bị che. Copy/reveal, clipboard timeout, lock/sleep cleanup và
  approval digest phải giữ đúng security semantics hiện tại.
- Search phải debounce và không cho response cũ ghi đè query mới.
- Edit dùng draft state; Save/Cancel, validation và retry không làm mất dữ liệu.
- Không giả API/backend capability để khớp prototype. Nếu IPC thiếu field, ghi rõ
  evidence và chọn bỏ UI đó hoặc bổ sung contract có test.

Prototype HTML là hợp đồng về hierarchy, density, state và interaction, không
phải yêu cầu port CSS pixel-by-pixel. Ưu tiên UX native quan trọng của macOS qua
platform adapter trong khi giữ visual language chung bằng Forui.

Trong quá trình làm:

- Bảo toàn mọi thay đổi có sẵn không thuộc task; không reset hoặc ghi đè chúng.
- Dùng thay đổi nhỏ, có thể review. Sau mỗi phase, chạy formatter, flutter analyze,
  test liên quan và build target thích hợp.
- Thêm/sửa widget tests cho state routing, responsive shell, search race, draft
  preservation và các security-sensitive transitions.
- Kiểm tra tối thiểu 800×600 và 1280×800, light/dark, keyboard navigation và
  overflow. Các kiểm thử cần Mac thật như VoiceOver phải được chạy thật hoặc ghi
  rõ là chưa xác minh; không suy diễn từ HTML/widget test.
- Nếu gặp khác biệt API do version Forui/toolchain, tra official docs/changelog,
  sửa theo version đã pin và ghi lại quyết định ngắn gọn trong docs.

Definition of done là checklist trong docs/macos-ui-ux-improvement-plan.md.
Khi kết thúc, báo cáo:

1. Phase và acceptance item nào đã hoàn tất/chưa hoàn tất.
2. File và kiến trúc chính đã thay đổi.
3. Lệnh kiểm chứng đã chạy cùng kết quả thực tế.
4. Những điểm chưa kiểm chứng trên thiết bị thật hoặc blocker còn lại.
5. Không tuyên bố hoàn tất toàn bộ plan nếu checklist chưa đạt.
```
