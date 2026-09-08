# Build và kiểm tra KeyLease trên macOS Intel x86_64

Tài liệu này dành riêng cho Mac Intel 64-bit (`x86_64-apple-darwin`). Project
đặt deployment target là macOS 13.0 để dùng Login Items qua `SMAppService`. Các bước dưới đây build cả Rust CLI/daemon
và Flutter app, sau đó kiểm tra IPC, lock, clipboard, KDBX và connector flow.

> Flutter đã thông báo sẽ ngừng hỗ trợ host Intel trong một bản tương lai. Để
> kết quả có thể lặp lại, dùng Flutter 3.47.2 cho lần acceptance này và không
> chạy `flutter upgrade` trước khi hoàn tất checklist.

## 1. Chuẩn bị máy

Yêu cầu:

- Mac Intel chạy macOS 13 trở lên; `uname -m` phải trả `x86_64`.
- Xcode bản mới nhất mà phiên bản macOS trên máy hỗ trợ.
- Flutter 3.47.2 stable bản Intel.
- Rust 1.98.0; repo tự pin bằng `rust-toolchain.toml`.
- Git và một SSH key đã được thêm vào GitHub.

Cài và khởi tạo Xcode command-line tools:

```sh
xcode-select --install
sudo sh -c 'xcode-select -s /Applications/Xcode.app/Contents/Developer && xcodebuild -runFirstLaunch'
sudo xcodebuild -license
```

Tải Flutter 3.47.2 Intel từ Flutter SDK archive, giải nén vào một thư mục không
có khoảng trắng, rồi thêm `bin` vào `PATH`. Ví dụ:

```sh
mkdir -p "$HOME/Developer"
git clone --depth 1 --branch 3.47.2 https://github.com/flutter/flutter.git "$HOME/Developer/flutter-3.47.2"
echo 'export PATH="$HOME/Developer/flutter-3.47.2/bin:$PATH"' >> "$HOME/.zprofile"
export PATH="$HOME/Developer/flutter-3.47.2/bin:$PATH"
flutter config --enable-macos-desktop
flutter doctor -v
flutter devices
```

`flutter doctor -v` không được báo lỗi ở phần Xcode và `flutter devices` phải có
thiết bị `macOS`. Project hiện không dùng CocoaPods plugin; nếu sau này thêm
native plugin thì cài CocoaPods theo hướng dẫn của Flutter.

Cài Rust bằng rustup:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install 1.98.0 --profile minimal --component clippy,rustfmt
rustup target add x86_64-apple-darwin --toolchain 1.98.0
```

Kiểm tra kiến trúc và phiên bản:

```sh
uname -m
rustc -vV
flutter --version
xcodebuild -version
```

Kết quả Rust phải chứa `host: x86_64-apple-darwin`; Flutter phải là 3.47.2.

## 2. Clone source

```sh
ssh -T git@github.com
git clone git@github.com:ai1-maker/leasegate.git
cd leasegate
```

Lệnh `ssh -T` của GitHub thường kết thúc với status 1 dù xác thực thành công;
hãy kiểm tra output có câu xác nhận đã authenticated.

## 3. Chạy toàn bộ automated checks

Script sau dừng ngay khi sai platform, architecture, formatter, test, lint,
codesign hoặc output binary:

```sh
chmod +x scripts/macos-x86_64-check.sh
./scripts/macos-x86_64-check.sh
```

Nó thực hiện:

```text
cargo fmt --check
cargo test --workspace
cargo clippy -D warnings
cargo build --release -p keylease-cli
flutter pub get
dart format --check
flutter analyze
flutter test
flutter build macos --release
lipo architecture checks
codesign verification
```

Output mong đợi:

```text
target/release/keylease
apps/desktop-flutter/build/macos/Build/Products/Release/KeyLease.app
```

Xác minh thủ công nếu cần:

```sh
lipo -archs target/release/keylease
lipo -archs apps/desktop-flutter/build/macos/Build/Products/Release/KeyLease.app/Contents/MacOS/KeyLease
```

Cả hai lệnh phải chứa `x86_64`.

## 4. Tạo vault kiểm thử tách biệt

Không dùng vault thật. Tạo một thư mục tạm chỉ owner có quyền truy cập:

```sh
export KEYLEASE_TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/keylease-macos-x86.XXXXXX")"
chmod 700 "$KEYLEASE_TEST_DIR"
export KEYLEASE_DB="$KEYLEASE_TEST_DIR/acceptance.sqlite"
export KEYLEASE_SOCKET="/tmp/keylease-$USER.sock"
export KEYLEASE_TOKEN="$KEYLEASE_TEST_DIR/desktop.token"
export KEYLEASE_BIN="$PWD/target/release/keylease"
```

Khởi tạo vault. Password chỉ được nhập trực tiếp trong TTY, không đặt trong
environment variable hoặc command argument:

```sh
KEYLEASE_INIT_JSON="$($KEYLEASE_BIN --db "$KEYLEASE_DB" vault init)"
printf '%s\n' "$KEYLEASE_INIT_JSON"
export KEYLEASE_VAULT_ID="$(printf '%s\n' "$KEYLEASE_INIT_JSON" | sed -E 's/.*"vault_id":"([^"]+)".*/\1/')"
```

Đăng ký desktop client và lưu token với mode 0600:

```sh
KEYLEASE_REGISTRATION="$($KEYLEASE_BIN --db "$KEYLEASE_DB" client register desktop)"
printf '%s\n' "$KEYLEASE_REGISTRATION" | sed -E 's/.*"client_token":"([^"]+)".*/\1/' > "$KEYLEASE_TOKEN"
chmod 600 "$KEYLEASE_TOKEN"
unset KEYLEASE_REGISTRATION
```

Tạo grant dành cho acceptance UI. Đây là grant rộng cho vault test; không sao
chép nguyên cấu hình này sang vault production:

```sh
$KEYLEASE_BIN --db "$KEYLEASE_DB" grant create \
  --client agent_desktop \
  --resource "kl://$KEYLEASE_VAULT_ID" \
  --allow entry:search,entry:read_metadata,entry:read_username,entry:read_secret,entry:create,entry:update_standard_fields,entry:update_protected_fields,entry:update_totp,entry:move,entry:delete,group:create,group:update,group:delete,connection:list,connection:add,connection:enroll,connection:unenroll,connection:test,connection:refresh,connection:disconnect,connection:revoke,approval:list,approval:decide,audit:query \
  --ttl-seconds 28800 \
  --max-lease-ttl-seconds 600
```

Mỗi command quản trị ở trên sẽ hỏi master password qua TTY.

## 5. Chạy daemon và app

Terminal A:

```sh
cd /path/to/leasegate
target/release/keylease \
  --db "$KEYLEASE_DB" \
  --socket "$KEYLEASE_SOCKET" \
  serve --start-locked --session-ttl-seconds 28800
```

Terminal B:

```sh
open apps/desktop-flutter/build/macos/Build/Products/Release/KeyLease.app
```

Trong app:

1. Mở **Settings**.
2. Socket: giá trị của `KEYLEASE_SOCKET`, mặc định `/tmp/keylease-$USER.sock`.
3. Client ID: `agent_desktop`.
4. Chọn `desktop.token` bằng nút file picker; không nhập path symlink.
5. Nhấn **Connect**, sau đó **Unlock** và nhập master password.

Nếu app báo token không hợp lệ, kiểm tra:

```sh
stat -f '%Sp %N' "$KEYLEASE_TOKEN"
```

Quyền phải là `-rw-------`. App chủ động từ chối symlink, file rỗng, file quá
lớn và token cho group/others đọc được.

## 6. Checklist chức năng vault

Thực hiện lần lượt và ghi Pass/Fail cùng screenshot hoặc console output:

- Tạo hai group, rename một group và xóa một group rỗng.
- Tạo đủ bốn template: Login, API Credential, Secure Note và Generic item.
- Tạo Login có username, password, URL, notes, custom field protected và TOTP
  bằng Base32; tạo thêm một entry bằng URI `otpauth://`.
- Search theo title, username và URL.
- Edit title/URL/notes, đổi password, thay TOTP và di chuyển entry sang group kia.
- Mở password: mặc định phải bị che, nút Reveal/Hide phải hoạt động.
- Copy username/password/TOTP và xác nhận Audit chỉ có tên field, không có value.
- Mở History sau ít nhất một update và kiểm tra revision cũ xuất hiện.
- Delete entry và xác nhận nó biến mất khỏi danh sách active.
- Bấm Lock; mọi view nhạy cảm phải bị xóa và request sau đó trả `vault_locked`.

## 7. Checklist clipboard và lifecycle macOS

Sau khi copy một password test:

```sh
pbpaste
sleep 31
pbpaste
```

Lần đầu phải trả password test; lần sau phải rỗng. Kiểm tra thêm tính an toàn:

1. Copy password từ KeyLease.
2. Ngay lập tức copy chuỗi `do-not-delete` từ ứng dụng khác.
3. Chờ hơn 30 giây; KeyLease không được xóa clipboard mới của người dùng.
4. Copy lại password, rồi lock thủ công; clipboard phải được xóa ngay.
5. Copy lại password, nhấn `Control-Command-Q`, đăng nhập lại; vault phải locked
   và clipboard phải rỗng.
6. Lặp lại với sleep/wake nếu máy test cho phép.

## 8. Kiểm tra CLI/daemon headless

Trong khi daemon chạy, đặt các biến dùng cho client CLI:

```sh
export KEYLEASE_AGENT_ID=agent_desktop
```

Các lệnh mẫu:

```sh
$KEYLEASE_BIN --socket "$KEYLEASE_SOCKET" \
  --agent-id "$KEYLEASE_AGENT_ID" --client-token-file "$KEYLEASE_TOKEN" status

$KEYLEASE_BIN --socket "$KEYLEASE_SOCKET" \
  --agent-id "$KEYLEASE_AGENT_ID" --client-token-file "$KEYLEASE_TOKEN" \
  entries search github

printf '%s\n' '{"group_id":"GROUP_ID","kind":"core.login","title":"CLI test","username":"agent","password":"temporary-only","url":"https://example.test","notes":null,"custom_fields":[],"totp":null,"totp_uri":null}' | \
  $KEYLEASE_BIN --socket "$KEYLEASE_SOCKET" \
    --agent-id "$KEYLEASE_AGENT_ID" --client-token-file "$KEYLEASE_TOKEN" \
    entries create --input-json - --idempotency-key macos-cli-001
```

Thay `GROUP_ID` bằng ID thật từ app hoặc `groups list`. Xác nhận:

- JSON stdout không lẫn progress/warning.
- Password không xuất hiện trong error hoặc audit.
- Gửi lại cùng idempotency key không tạo item thứ hai.
- Update với revision sai trả `revision_conflict`.
- Token sai, token mode 0644 và symlink đều bị từ chối.
- Sau khi daemon restart, idempotency replay và audit vẫn còn.

## 9. KDBX và 1PUX acceptance

### KDBX

Dùng một fixture KDBX 4.0/4.1 được tạo bởi Strongbox hoặc KeePassXC, gồm custom
fields, protected fields và TOTP:

```sh
$KEYLEASE_BIN --db "$KEYLEASE_DB" vault import-kdbx /path/to/fixture.kdbx
$KEYLEASE_BIN --db "$KEYLEASE_DB" vault import-kdbx /path/to/fixture.kdbx --commit
$KEYLEASE_BIN --db "$KEYLEASE_DB" vault export-kdbx "$KEYLEASE_TEST_DIR/export.kdbx"
```

Kiểm tra preview trước commit. Mở `export.kdbx` bằng cả Strongbox và KeePassXC,
đối chiếu title, username, password, URL, notes, custom/protected fields, TOTP,
groups và history. Agent grants, audit và connection credentials không được xuất.

### 1PUX

Chỉ dùng export test. 1PUX là plaintext nên giữ trong thư mục tạm, không commit,
không đưa vào backup/index:

```sh
$KEYLEASE_BIN --db "$KEYLEASE_DB" vault import-onepux /path/to/test.1pux \
  --acknowledge-plaintext
$KEYLEASE_BIN --db "$KEYLEASE_DB" vault import-onepux /path/to/test.1pux \
  --acknowledge-plaintext --commit
```

Đối chiếu sections, typed fields, history, attachments, warning và source
checksum trong migration report.

## 10. Connector acceptance

### Google Workspace

Tạo OAuth client loại Desktop app và cấp đúng scope `drive.file`. Trong tab
Connections chọn **Connect Google**, nhập client ID, hoàn tất browser Picker và
chọn một Doc, một Sheet cùng một folder test.

Xác nhận:

- Chỉ các ID vừa chọn xuất hiện trong authorized resources.
- Không thể list/search toàn Drive hoặc đọc file chưa chọn.
- Đọc Doc trả `untrusted_content=true` và không lộ OAuth token.
- Sheet read/append chỉ chạy trong bounded range đã grant.
- Update với `expected_values_hash` sai bị deny.
- `USER_ENTERED`, formula write, sharing, clear và delete không tồn tại hoặc bị deny.
- Lock trong khi OAuth flow đang chờ làm flow hết hiệu lực.

### GitHub, Linear và Notion beta

Với test organizations/workspaces tách biệt, kiểm tra từng action catalog,
resource ID ổn định, deny-by-default, refresh/revoke và token redaction. Không
dùng production token. GitHub phải giới hạn repository; Linear giới hạn
workspace/team; Notion chỉ dùng page đã share trực tiếp.

## 11. Kiểm tra release bundle và signing

Build release đã được script tạo. Kiểm tra bundle:

```sh
codesign --verify --deep --strict --verbose=2 \
  apps/desktop-flutter/build/macos/Build/Products/Release/KeyLease.app

codesign -d --entitlements :- \
  apps/desktop-flutter/build/macos/Build/Products/Release/KeyLease.app

open apps/desktop-flutter/macos/Runner.xcworkspace
```

Xác nhận Release entitlements có App Sandbox, network client và user-selected
read-only file access. Để phát hành ngoài máy test cần Apple Developer signing,
Hardened Runtime và notarization; build ad-hoc local không phải artifact phát hành.

## 12. Báo cáo kết quả

Ghi lại tối thiểu:

- Model Mac, CPU, RAM, macOS và Xcode version.
- `rustc -vV`, `flutter --version`, commit SHA được test.
- Output của script automated check.
- Pass/Fail cho từng mục vault, clipboard, lock, KDBX/1PUX và connectors.
- Crash log đã redact, nếu có; không đính kèm database/token/plaintext fixtures.
- SHA-256 của CLI và app executable:

```sh
shasum -a 256 target/release/keylease
shasum -a 256 apps/desktop-flutter/build/macos/Build/Products/Release/KeyLease.app/Contents/MacOS/KeyLease
git rev-parse HEAD
```

Sau khi xong, đóng app/daemon và xóa riêng thư mục acceptance tạm:

```sh
case "$KEYLEASE_TEST_DIR" in
  "${TMPDIR:-/tmp}"/keylease-macos-x86.*) rm -rf -- "$KEYLEASE_TEST_DIR" ;;
  *) printf 'Refusing unexpected test directory: %s\n' "$KEYLEASE_TEST_DIR" >&2 ;;
esac

if [ "$KEYLEASE_SOCKET" = "/tmp/keylease-$USER.sock" ] && [ -S "$KEYLEASE_SOCKET" ]; then
  rm -f -- "$KEYLEASE_SOCKET"
fi
```

Không chạy hai lệnh trên nếu biến không còn trỏ đúng thư mục/socket acceptance.

## Tài liệu chính thức tham khảo

- Flutter: https://docs.flutter.dev/platform-integration/macos/setup
- Flutter macOS build: https://docs.flutter.dev/platform-integration/macos/building
- Flutter manual install và cảnh báo Intel: https://docs.flutter.dev/install/manual
- Rustup: https://rust-lang.github.io/rustup/installation/index.html
- Rust macOS targets: https://doc.rust-lang.org/rustc/platform-support/apple-darwin.html
- GitHub SSH: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/testing-your-ssh-connection
