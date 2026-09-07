# Spike đối chứng `macos_ui` (đã archive)

Ngày 2026-09-07 dự án chốt Forui cho production. File trong thư mục này là bản
lưu của spike `macos_ui` để đối chiếu shell macOS, **không** phải mã production.

- Nằm ngoài `lib/`, nên không được biên dịch vào app.
- `analysis_options.yaml` loại `spikes/**` khỏi analyzer.
- `macos_ui` đã bị gỡ khỏi `pubspec.yaml`. Muốn chạy lại spike phải thêm tạm
  `macos_ui` (bản tương thích Flutter 3.47.x), copy file vào `lib/`, rồi hoàn
  nguyên trước khi commit.

Kết quả so sánh và giới hạn kiểm tra: [../../UI_SPIKES.md](../../UI_SPIKES.md).
