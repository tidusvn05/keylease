# KeyLease — đề xuất universal secret vault và access gateway cho agent

## 1. Tóm tắt quyết định

Xây dựng **KeyLease**, một universal secret vault local-first, agent-friendly, có kiến trúc sẵn sàng phát triển thành sản phẩm cloud zero-knowledge và access gateway cho agent.

Các quyết định đã chốt:

- Native encrypted object model là source of truth.
- KDBX, 1PUX và Credential Exchange là import/export adapters, không định nghĩa giới hạn của sản phẩm.
- Domain model hỗ trợ nhiều loại secret ngay từ đầu.
- Hỗ trợ import KDBX từ Strongbox/KeePassXC và export KDBX cho khả năng chuyển đổi dữ liệu.
- Có thể cân nhắc external KDBX mode riêng, nhưng vault này không tham gia cloud sync và không phải default.
- First version dành cho macOS.
- Mobile tương lai gồm cả iOS và Android.
- First version chỉ unlock bằng master password.
- Flutter phụ trách UI đa nền tảng.
- Rust phụ trách crypto, native storage, interoperability, business logic và vault service.
- Agent CLI có thể đọc và ghi ngay từ first version.
- First version đưa một lát cắt LeaseGate local vào MVP để agent có thể dùng connector mà không nhận upstream credential.
- Thứ tự triển khai connector: Fake Connector, Google Workspace, GitHub, Linear và Notion.
- Google Workspace là flagship connector, gồm Drive, Docs và Sheets trên cùng một connection.
- Chưa cần phát hành MCP trong first version; connector được gọi qua CLI, nhưng command API phải sẵn sàng cho MCP adapter sau này.
- **KeyLease** là tên sản phẩm tổng thể; **LeaseGate** là gateway cloud/edge cấp quyền truy cập ngắn hạn cho agent.
- Định vị dài hạn: **Secure secrets. Lease access.** Agent nhận access lease có scope và TTL thay vì secret dài hạn.

## 2. Nguyên tắc sản phẩm

KeyLease là một universal secret vault có khả năng tương tác với hệ sinh thái password manager và tiến tới credential broker cho agent. KeePass compatibility là một product feature quan trọng, nhưng KDBX không còn là internal storage model.

Các nguyên tắc cốt lõi:

- Local-first: first version hoạt động đầy đủ khi chưa có backend.
- Cloud-ready: storage, key hierarchy, revision và sync model được thiết kế trước khi phát hành local version.
- Native encrypted object model luôn là source of truth cho native vault.
- Không lưu bản plaintext của vault vào SQLite, cache, log hoặc crash report.
- Import/export phải tạo migration report và không âm thầm bỏ qua dữ liệu không ánh xạ được.
- Agent được xem là một client có quyền giới hạn, không phải chủ sở hữu toàn quyền của vault.
- Mặc định từ chối quyền; chỉ cho phép những capability đã được người dùng cấp rõ ràng.

## 3. Kiến trúc tổng thể

```text
Flutter macOS/iOS/Android ─┐
Agent CLI ─────────────────┼── Rust Vault Service ── Native encrypted store
MCP adapter (tương lai) ───┘           │
                                       ├── LeaseGate local PEP
                                       │     └── Connector runtime
                                       │          ├── Google Workspace
                                       │          ├── GitHub
                                       │          ├── Linear
                                       │          └── Notion
                                       ├── Cloud sync protocol
                                       └── Import/export adapters
                                            ├── KDBX
                                            ├── 1PUX import
                                            └── CXF/CXP
```

`keylease serve` là tiến trình duy nhất được phép giữ decrypted keys và thực hiện mutations. Flutter, CLI, MCP và import/export adapters không tự bypass command/policy layer.

Kiến trúc này giúp:

- Giữ native domain model độc lập với KDBX, 1PUX hoặc backend database.
- Tránh Flutter và CLI trở thành hai writer cạnh tranh.
- Dùng chung policy, audit, conflict detection và file safety.
- Bổ sung MCP mà không viết lại business logic.
- Tái sử dụng Rust core trên macOS, iOS và Android.

### Cấu trúc workspace đề xuất

```text
crates/
  vault-domain/       Entry, Group, Field, Vault
  vault-crypto/       Key hierarchy, envelope và item encryption
  native-store/       Local encrypted object repository
  kdbx-adapter/       Đọc và ghi KDBX
  onepux-adapter/     Import 1Password 1PUX
  exchange-adapter/   CXF/CXP và platform credential exchange
  sync-protocol/      Version, mutation log, tombstone, conflict
  vault-commands/     Search, create, update, delete, copy
  vault-policy/       Client identity, capability và approval
  leasegate-policy/   Typed action policy, access lease và budgets
  leasegate-connectors/ Connector runtime, manifests và built-in connectors
  vault-service/      Session, lock, save, conflict
  vault-ipc/          Versioned local IPC protocol
  vault-cli/          CLI cho người dùng, script và agent
  vault-mcp/          MCP adapter trong tương lai

apps/
  desktop-flutter/    Ứng dụng macOS

interop-fixtures/     Fixtures KDBX, 1PUX, CXF và migration reports
connector-fixtures/   Fake provider, OAuth failures, replay và redaction cases
```

## 4. Tech stack

### Flutter/Dart

Flutter phụ trách:

- UI macOS.
- Navigation và application state.
- Group tree và entry list.
- Search.
- Form tạo và chỉnh sửa entry.
- TOTP countdown.
- Dialog conflict, approval và error.

Có thể sử dụng Riverpod cho state management. Không đặt logic KDBX hoặc policy bảo mật trong Dart.

### Rust

Rust phụ trách:

- Đọc và giải mã KDBX.
- Native encrypted object store và key hierarchy.
- Import/export KDBX, 1PUX và các exchange formats.
- Domain model cho vault, group, entry và custom field.
- Tạo, sửa, xóa và di chuyển entry/group.
- TOTP parsing và generation.
- Password generator.
- Session và auto-lock.
- Conflict detection.
- Backup, validation và atomic save.
- Agent authorization và audit.
- Zeroize dữ liệu nhạy cảm khi có thể.

Rust crate `keepass` là ứng viên ban đầu cho interoperability nhưng phải được bọc sau `KdbxAdapter`. Không để domain model hoặc native persistence phụ thuộc trực tiếp vào API của thư viện.

### Native platform adapter

Phần native macOS viết bằng Swift phụ trách:

- System file picker.
- Security-scoped bookmark.
- Clipboard và clipboard timeout.
- Theo dõi sleep/wake và session lock.
- Keychain/Touch ID trong phiên bản sau.

Flutter và Rust kết nối bằng `flutter_rust_bridge` hoặc IPC tùy process boundary. Flutter không được nhận toàn bộ decrypted vault nếu chỉ cần metadata cho màn hình hiện tại.

## 5. Storage và interoperability

### Native vault mode — default

- Tạo vault mới bằng native encrypted object model.
- Local store giữ encrypted objects, revisions, tombstones và mutation log.
- Sau này cùng object model được đồng bộ dưới dạng ciphertext qua cloud.
- Đây là mode hỗ trợ đầy đủ item kinds, sharing, agent grants, rotation và multi-device.

### Import

- KDBX 3.1/4.0/4.1 từ Strongbox, KeePass và KeePassXC.
- 1Password `.1pux`; file này là ZIP chứa JSON và attachments nhưng hoàn toàn không được mã hóa.
- CSV chỉ là fallback cho login đơn giản.
- CXF/CXP hoặc platform Credential Exchange khi platform hỗ trợ.

Mỗi import phải chạy theo hai bước: preview mapping rồi commit. Kết quả có migration report gồm số item thành công, warning, unsupported fields, duplicate decisions và checksum nguồn.

### Export

- Native encrypted backup format là định dạng full-fidelity và được khuyến nghị.
- KDBX 4.1 là portable compatibility export cho Strongbox/KeePass/KeePassXC.
- CSV plaintext chỉ khi người dùng xác nhận cảnh báo mạnh.
- CXF/CXP là hướng ưu tiên để chuyển passwords/passkeys trực tiếp giữa credential providers.
- Không cam kết tạo 1PUX như primary export contract. 1PUX là format unencrypted của 1Password và có nhiều thuộc tính riêng; để chuyển sang 1Password, ưu tiên KDBX/CSV mà 1Password hỗ trợ hoặc Credential Exchange trên platform.

### External KDBX mode — optional

Nếu vẫn cần hai app chỉnh sửa cùng một KDBX, cung cấp một mode riêng:

- Mở file tại chỗ bằng security-scoped bookmark.
- Không cloud-sync file đó qua native sync engine.
- Không hỗ trợ các feature không thể round-trip losslessly.
- Phát hiện external modification trước mỗi save.
- Gắn nhãn rõ `External KeePass Vault` thay vì native vault.

Mode này nên là compatibility feature, không phải onboarding mặc định.

## 6. Mutation, local persistence và sync

Mỗi mutation từ GUI hoặc agent phải có actor, base revision, idempotency key và encrypted payload result.

Native store ghi transaction atomically và append mutation metadata. Secret plaintext chỉ tồn tại trong Vault Service khi cần. Cloud server nhận ciphertext, opaque identifiers, revision/tombstone và tối thiểu metadata vận hành cần thiết.

Conflict được xử lý ở item/field level khi an toàn. Không tự động merge hai password/TOTP/private-key values khác nhau; tạo conflict cần người dùng hoặc policy rõ ràng giải quyết.

Với external KDBX mode, tiếp tục dùng temporary write, reopen validation, backup, fingerprint check và atomic replace. First version không tự động merge KDBX.

## 7. TOTP compatibility

TOTP trong hệ sinh thái KeePass có nhiều cách lưu khác nhau.

Ứng dụng nên:

- Native model lưu TOTP bằng typed fields gồm secret, issuer, account, algorithm, digits và period.
- Khi export KDBX, ưu tiên custom field protected `otp` chứa URI `otpauth://totp/...`.
- Khi import KDBX, hỗ trợ `otp` và các field KeePass như `TimeOtp-Secret-Base32`, `TimeOtp-Period`, `TimeOtp-Length` và `TimeOtp-Algorithm`.
- Không tự động chuyển representation nếu người dùng chưa chỉnh sửa TOTP.
- Test round-trip với Strongbox, KeePassXC và KeePass.

## 8. Phạm vi chức năng first version

### Vault

- Tạo native local encrypted vault.
- Import local `.kdbx` vào native vault.
- Export native vault hoặc selected items sang KDBX.
- External KDBX open-in-place là optional compatibility scope, không phải điều kiện bắt buộc để ra first version.
- Unlock bằng master password.
- Lock thủ công.
- Auto-lock theo thời gian không hoạt động.
- Lock khi máy sleep hoặc session bị khóa.
- Recent vaults bằng security-scoped bookmarks.

### Entry và group

- Hiển thị group tree.
- Hiển thị danh sách entry.
- Search theo title, username và URL.
- Tạo, sửa, xóa entry.
- Tạo, đổi tên và xóa group.
- Di chuyển entry giữa các group.
- Các field chuẩn: Title, Username, Password, URL và Notes.
- Custom fields có protected/unprotected flag.
- Mỗi entry có `kind` mở rộng được thay vì chỉ có loại account/login.
- First version có template cho Login, API Credential và Secure Note.
- Data model đã có thể biểu diễn SSH Key, Database Credential, Environment Bundle, Certificate và Recovery Codes dù UI chuyên biệt có thể triển khai sau.

### Password và TOTP

- Reveal/hide password.
- Copy username/password.
- Tự xóa clipboard sau khoảng thời gian cấu hình.
- Password generator.
- Thêm TOTP bằng secret hoặc `otpauth://`.
- Hiển thị code và countdown.
- Copy TOTP.

### Agent CLI

- CLI có thể search, read metadata, tạo và cập nhật entry ngay trong first version.
- Agent có thể write nhưng chỉ trong phạm vi capability grant.
- CLI hỗ trợ JSON input/output ổn định.
- Mutation hỗ trợ revision check và idempotency key.
- Audit log không chứa secret.

### LeaseGate local và connector runtime

First version phải có một vertical slice LeaseGate local đủ để connector thực hiện action mà không trả upstream access token, refresh token hoặc API key cho agent.

Phạm vi tối thiểu:

- `keylease serve` là local policy enforcement point và connector runtime.
- Connection lifecycle gồm connect, test, refresh, disconnect và revoke.
- Connection credential được mã hóa trong native vault; connection metadata tách khỏi item payload.
- Canonical typed action và resource ID được kiểm tra trước mọi downstream side effect.
- Opaque execution lease có TTL, `max_uses`, revoke và kill switch.
- Write action bind với exact canonical request và local approval khi policy yêu cầu.
- Idempotency journal ngăn retry tạo side effect trùng.
- Response filtering, data budget và audit dùng chung cho mọi connector.
- Connector được gọi qua CLI trong first version; MCP vẫn là transport adapter tương lai.

### Thứ tự connector trong first version

Thứ tự triển khai kỹ thuật khác với thứ tự giá trị người dùng:

```text
Engineering:   Fake Connector → Google Workspace → GitHub → Linear → Notion
User value:    Google Workspace → GitHub → Linear → Notion
```

| Connector | Mức phát hành first version | Vai trò |
|---|---|---|
| Fake Connector | Internal, bắt buộc | Conformance, fault injection và security regression |
| Google Workspace | Production, launch-blocking | Flagship knowledge-work connector |
| GitHub | Public beta | Developer workflow connector |
| Linear | Private beta | Issue và comment workflow |
| Notion | Private beta | Page/document workflow |

Không tính Fake Connector là một connector thương mại. GitHub, Linear và Notion chỉ được nâng lên production sau khi pass cùng conformance suite và có đủ telemetry về authorization, refresh và side-effect failures.

### Google Workspace Connector

Google Workspace là một connection duy nhất với ba module dùng chung identity, OAuth lifecycle, resource registry và policy:

```text
Google Workspace Connection
  ├── Google Drive
  ├── Google Docs
  └── Google Sheets
```

First version chỉ dùng per-file access thông qua OAuth scope `drive.file` và Google Picker. Người dùng chọn rõ file nào được thêm vào connection; agent không được search hoặc enumerate toàn bộ Drive.

Google Drive actions:

- `google_drive.file.list_authorized`
- `google_drive.file.get_metadata`
- `google_drive.file.export_text`

Google Docs actions:

- `google_docs.document.get`
- `google_docs.document.create`
- `google_docs.document.append`
- `google_docs.document.update`

Google Sheets actions:

- `google_sheets.spreadsheet.get_metadata`
- `google_sheets.values.read`
- `google_sheets.values.batch_read`
- `google_sheets.rows.append`
- `google_sheets.values.update`
- `google_sheets.spreadsheet.create`

Google Workspace policy phải bind với stable Google file ID. Với Sheets, policy bind thêm `sheet_id` và A1/Grid range cụ thể; không authorize chỉ bằng tên tab có thể đổi hoặc trùng.

Risk mặc định:

| Action | Risk | Chính sách mặc định |
|---|---|---|
| Đọc metadata | R0 | Grant theo file |
| Đọc document hoặc sheet range | R1 | Grant + item/cell/byte budget |
| Tạo document hoặc spreadsheet | R2 | Short lease + idempotency |
| Append rows/content | R2 | Short lease + bounded target |
| Update existing content/cells | R3 | Exact-request approval |
| Share, permission, ownership, clear hoặc delete | R4 | Không hỗ trợ trong first version |

Giới hạn Google Sheets:

- Không expose raw `spreadsheets.batchUpdate` request cho agent.
- Mọi read/write có giới hạn số range, row, column, cell và response bytes.
- Write dùng `valueInputOption=RAW` mặc định để dữ liệu bắt đầu bằng `=` không tự trở thành formula.
- Thiết kế capability riêng `google_sheets.formula.write`, nhưng không implement trong first version.
- Không hỗ trợ clear range, delete sheet, protected-range mutation, external data source hoặc sharing permission.
- Append có thể dùng standing grant trong một range/table đã định.
- Update existing cells phải mang `expected_values_hash`; LeaseGate đọc lại range ngay trước execution và fail nếu state đã đổi.
- Sheets batch operation có thể atomic cho chính batch đó nhưng không phải compare-and-set với collaborator edits; không quảng cáo `expected_values_hash` như một cryptographic hoặc transaction boundary tuyệt đối.

Giới hạn Google Docs:

- Update phải dùng document revision precondition khi API hỗ trợ.
- Approval hiển thị semantic diff thay vì chỉ raw request.
- Không thay toàn bộ document nếu policy chỉ cho append hoặc targeted update.

Mọi Drive, Docs và Sheets content trả về agent phải được đánh dấu là untrusted external content. Audit chỉ ghi file/spreadsheet ID, range, revision, item/cell count và byte count; không ghi document text hoặc cell values.

### GitHub Connector

First version dùng GitHub App authorization phù hợp cho desktop/CLI và giới hạn connection theo repositories được chọn. LeaseGate giữ access/refresh token và không trả token cho agent.

Actions:

- `github.repository.get_metadata`
- `github.issue.list`
- `github.issue.get`
- `github.issue.create`
- `github.issue.comment`
- `github.pull_request.list`
- `github.pull_request.get`
- `github.pull_request.create_draft`
- `github.pull_request.comment`
- `github.checks.read`

Không hỗ trợ merge, workflow dispatch, source-code write, release publish, Actions secrets/variables, repository settings, collaborators hoặc delete trong first version. Resource policy dùng canonical repository ID; `owner/name` chỉ là display alias và phải resolve lại trước authorization.

### Linear Connector

First version ưu tiên OAuth PKCE với `actor=app` để downstream audit phân biệt hành động của agent. Chỉ request các scope hẹp `read`, `issues:create` và `comments:create`; không request `write` hoặc `admin`.

Actions:

- `linear.issue.list`
- `linear.issue.get`
- `linear.issue.create`
- `linear.comment.create`

Hoãn update status, assign/delegate, project mutation, customer data và delete. Team/workspace ID phải được canonicalize trước policy evaluation.

### Notion Connector

First version chỉ truy cập page/data source đã được share trực tiếp với connection.

Actions:

- `notion.page.search_authorized`
- `notion.page.get_markdown`
- `notion.page.create`
- `notion.page.append_markdown`
- `notion.page.update_markdown`

Local-only MVP dùng BYO internal Notion connection token được nhập qua secure UI và mã hóa trong vault. Public one-click OAuth được triển khai khi có backend có thể bảo vệ OAuth client secret và callback flow.

Không hỗ trợ database schema mutation, workspace-wide search, permission, archive hoặc delete. Update phải bind với page ID, parent ID khi tạo và content digest/revision context phù hợp.

### Fake Connector

Fake Connector là executable specification cho connector contract, không chỉ là echo adapter. Nó phải mô phỏng:

- Access token và refresh token expiry.
- OAuth denial, revocation và invalid scope.
- Pagination, rate limit `429`, timeout và partial failure.
- Schema/version drift và unknown response fields.
- Idempotent và non-idempotent side effects.
- Resource aliases, rename và canonicalization attacks.
- Secret xuất hiện trong upstream error để kiểm tra redaction.
- Concurrent lease consumption, replay và daemon restart.

## 9. Agent-friendly security model

### Unlock flow

1. Người dùng mở GUI hoặc chạy secure interactive unlock command.
2. Người dùng nhập master password.
3. `keylease serve` giữ decrypted vault trong một session có TTL.
4. Agent CLI kết nối qua local IPC.
5. Mọi request được kiểm tra policy.
6. Khi vault auto-lock, mọi agent grant trong session hết hiệu lực.

Agent không được:

- Nhận master password.
- Truyền master password qua command argument, environment, JSON hoặc MCP.
- Tự unlock vault không có tương tác của người dùng.
- Dump toàn bộ decrypted vault.
- Tắt audit hoặc policy.

Nếu vault đang khóa, API trả structured error:

```json
{
  "error": "vault_locked",
  "requires_user_action": true
}
```

### Client identity và capability grant

CLI không thể tự xác định process đang được gọi bởi người hay agent. Vì vậy quyền phải gắn với client identity.

Ví dụ đăng ký và cấp quyền:

```bash
keylease client register codex

keylease grant create \
  --client codex \
  --group Development \
  --allow read-metadata,create-entry,update-entry \
  --ttl 8h
```

Grant có thể giới hạn theo:

- Vault.
- Group.
- Entry.
- Field.
- Loại hành động.
- TTL.
- Số lần sử dụng.
- Client identity.

`Capability grant` là standing authorization/policy do người dùng cấu hình; nó không phải credential mà agent dùng trực tiếp. Khi LeaseGate được bật, mỗi lần sử dụng thực tế phải tạo một `Access Lease` ngắn hạn nằm trong giới hạn của grant. Grant 8 giờ có thể cho phép request lease, nhưng từng lease chỉ nên sống vài phút hoặc một action.

### Capability đề xuất

- `entry:search`
- `entry:read_metadata`
- `entry:read_username`
- `entry:read_secret` — exceptional capability cho human/legacy workflow; agent mặc định không có.
- `entry:create`
- `entry:update_standard_fields`
- `entry:update_protected_fields`
- `entry:update_totp`
- `entry:move`
- `entry:delete`
- `group:create`
- `group:update`
- `group:delete`

Không nên có một quyền quá rộng như `vault:write` trong first version.

### Chính sách mặc định

| Hành động | Chính sách mặc định |
|---|---|
| Search và đọc metadata | Cho phép nếu grant |
| Tạo entry | Cho phép nếu grant cho group |
| Sửa title/URL/username/notes | Cho phép nếu grant |
| Đặt password mới | Cần protected-field grant |
| Đọc password hiện tại | Quyền riêng, mặc định deny; ưu tiên `use_secret`/LeaseGate |
| Thêm hoặc sửa TOTP | Cần quyền riêng |
| Di chuyển entry | Cần quyền riêng |
| Xóa entry | Approval mỗi lần hoặc grant rất ngắn |
| Xóa group | Không cho agent trong first version |
| Export plaintext | Không hỗ trợ |

Agent có thể được phép đặt password mới mà không được đọc password cũ.

Delete entry nên sử dụng KDBX recycle bin thay vì hard delete. Update phải giữ entry history khi format hỗ trợ.

## 10. Agent CLI contract

Ví dụ command:

```bash
keylease status --json
keylease entries search "github" --json
keylease entries get <id> --metadata-only --json

keylease entries create \
  --group-id grp_dev \
  --input-json - \
  --idempotency-key task-20260905-001

keylease entries update entry_123 \
  --patch-json - \
  --if-revision 42
```

Payload chứa secret phải truyền qua stdin, không nằm trong process arguments:

```json
{
  "set": {
    "title": "GitHub Bot",
    "username": "deploy-bot",
    "password": "generated-secret"
  }
}
```

CLI contract cần bảo đảm:

- Entry và group dùng UUID ổn định.
- `--json` không trộn progress hoặc warning vào stdout.
- Error code ổn định.
- Secret không xuất hiện trong error message.
- Secret không xuất hiện trong process arguments.
- Không cho truyền master password bằng CLI argument.
- Có dry-run cho mutation.
- Có idempotency key để retry an toàn.
- Có optimistic concurrency qua `--if-revision`.

Ví dụ conflict response:

```json
{
  "error": "revision_conflict",
  "expected": 42,
  "actual": 43,
  "retryable": false
}
```

## 11. Reveal secret và use secret

Vault và LeaseGate API phải phân biệt ngay từ first version:

- `reveal_secret`: trả plaintext về client.
- `copy_secret`: đưa secret vào clipboard.
- `use_secret`: sử dụng secret với một integration đã định mà không trả plaintext.
- `inject_secret`: cung cấp secret cho process cụ thể.
- `execute_action`: connector thực hiện typed downstream action mà không trả upstream credential.
- `read_resource`: trả external data đã được policy giới hạn theo resource và response budget.

Ưu tiên `use_secret` hoặc `execute_action` thay vì `reveal_secret`. `read_resource` chỉ dùng cho connector mà agent cần nhận dữ liệu như Drive, Docs, Sheets, Linear hoặc Notion; response phải được đánh dấu untrusted và audit không ghi raw content.

Không cung cấp API cho agent truyền arbitrary shell command cùng secret. Nếu agent có toàn quyền điều khiển process nhận secret thì không thể bảo đảm secret không bị in ra hoặc exfiltrate.

## 12. MCP hay CLI

First version chỉ cần CLI. MCP chưa cần thiết vì phần lớn coding agent đã có thể chạy shell và xử lý JSON.

Ưu điểm của CLI:

- Dễ test tự động.
- Dễ dùng trong script và CI.
- Ít dependency và attack surface hơn.
- Dễ kiểm soát exit code, timeout và retry.
- Không yêu cầu người dùng cấu hình MCP server.

MCP hữu ích trong tương lai khi:

- Agent host không cho phép chạy shell.
- Cần tool discovery tự động.
- Cần JSON Schema cho từng operation.
- Cần approval UX tích hợp với agent host.
- Cần hỗ trợ nhiều agent product bằng một integration chuẩn.

MCP không được gọi CLI như một shell subprocess. CLI, Flutter và MCP phải gọi trực tiếp cùng một `VaultCommandService`:

```text
                  ┌── keylease CLI
Vault Command API ├── Flutter
                  └── MCP adapter
```

Ví dụ command request dùng chung:

```rust
pub struct UpdateEntryRequest {
    pub actor: ActorContext,
    pub entry_id: EntryId,
    pub expected_revision: u64,
    pub patch: EntryPatch,
    pub idempotency_key: String,
}
```

MCP tools tương lai có thể gồm:

- `vault_status`
- `search_entries`
- `get_entry_metadata`
- `request_secret_access`
- `copy_field`
- `get_totp`
- `propose_create_entry`
- `propose_update_entry`
- `propose_delete_entry`

Không cung cấp:

- `dump_vault`
- `export_plaintext`
- `get_all_passwords`
- `execute_shell_with_secrets`
- `unlock_vault`
- `disable_audit`

## 13. Audit

Mỗi agent action ghi lại:

```json
{
  "timestamp": "2026-09-05T10:30:00Z",
  "client": "local-coding-agent",
  "action": "update_entry",
  "vault_id": "vault-id",
  "entry_id": "entry-id",
  "changed_fields": ["password"],
  "result": "success"
}
```

Audit log không chứa:

- Master password.
- Password field value.
- TOTP secret hoặc code.
- Protected custom-field value.
- Full request payload.

## 14. Technical spike bắt buộc

Trước khi triển khai toàn bộ MVP, cần chứng minh:

1. Chốt versioned crypto envelope, key hierarchy và threat model trước khi lưu dữ liệu thật.
2. Password change chỉ re-wrap Account Root Key, không re-encrypt tất cả item payloads.
3. Mỗi item được mã hóa bằng random item key và có thể rotate/re-wrap độc lập.
4. Native local store crash giữa transaction không tạo ciphertext hoặc revision state không nhất quán.
5. Mutation log có thể mô phỏng sync giữa hai device và phát hiện conflict deterministically.
6. Import được KDBX 4.0 và 4.1 do Strongbox tạo, gồm custom fields và TOTP.
7. Export KDBX có thể mở bằng Strongbox và KeePassXC, kèm loss report chính xác.
8. Import 1PUX giữ sections, typed fields, history và attachments trên bộ fixtures đã chọn.
9. Plaintext import file, temp file và secret không xuất hiện trong log/cache/backup ngoài ý muốn.
10. Agent retry với cùng idempotency key không tạo mutation trùng.
11. Agent không thể thực hiện action ngoài capability grant.
12. Domain/service tests không phụ thuộc vào KDBX adapter, chứng minh có thể đổi storage backend.
13. Fake Connector chứng minh deny unknown action/field, exact-request approval, replay protection và redaction trên mọi failure path.
14. Google Workspace OAuth connection chỉ nhìn thấy file do người dùng chọn bằng `drive.file`; không enumerate được toàn bộ Drive.
15. Drive, Docs và Sheets response budget chặn request vượt giới hạn item, cell hoặc byte trước khi trả content cho agent.
16. Google Sheets write mặc định lưu dữ liệu dạng raw, không âm thầm biến chuỗi thành formula; range ngoài policy luôn bị deny.
17. Connector retry, daemon restart và concurrent execution không vượt `max_uses` hoặc tạo downstream side effect trùng.

## 15. Ngoài phạm vi first version

- Key file.
- YubiKey hoặc hardware key.
- Touch ID unlock.
- Lưu master password vào Keychain.
- Browser extension.
- System AutoFill.
- Cloud sync riêng.
- Automatic merge.
- Passkeys.
- Attachment editing.
- CSV/XML/plaintext export.
- Mobile app hoàn chỉnh.
- MCP server production.
- Full-drive Google search bằng broad/restricted OAuth scope.
- Google Drive sharing, permission hoặc ownership mutation.
- Google Sheets formula write, clear/delete hoặc raw structural `batchUpdate`.
- GitHub merge, workflow dispatch, code/release/settings/IAM mutation.
- Linear admin/project/customer mutation.
- Notion workspace-wide search, permission, archive hoặc delete.

## 16. Lộ trình

Lộ trình phải ship theo vertical slices, nhưng mọi phase dùng chung target architecture và versioned contracts được mô tả tại phần LeaseGate. Không xây một local password manager rồi viết lại thành agent gateway.

1. **Phase 0 — Foundation contracts:** threat model, crypto envelope, identity model, action schema, policy decision contract, connector trait, Fake Connector conformance suite, audit schema và sync simulation.
2. **Phase 1 — KeyLease + LeaseGate Local MVP:** Rust core/CLI, macOS app, native encrypted store, KDBX import/export, local PEP, opaque execution lease, approval/revoke/audit, Google Workspace production và GitHub/Linear/Notion beta.
3. **Phase 2 — Connector hardening và LeaseGate Local Alpha:** productionize connectors theo usage, hoàn thiện refresh/health, budgets, policy UX và adversarial conformance.
4. **Phase 3 — KeyLease Cloud + LeaseGate Edge/MCP Beta:** E2EE vault sync, organization/project, cloud control plane, signed policy distribution, remote approval, edge gateway và scoped MCP endpoint tối thiểu.
5. **Phase 4 — Connector platform và policy UX:** OAuth connections, permission matrix, policy simulation, rate limits/budgets và connector SDK.
6. **Phase 5 — Dynamic/managed credentials:** token exchange, AWS-style STS, SSH certificates, database leases, optional managed cloud gateway và sender-constrained tokens.
7. **Phase 6 — Enterprise và mobile:** iOS/Android approval app, SSO/SCIM, SIEM export, policy-as-code, HA, BYOK/HSM và self-hosted control plane.

Mỗi phase có exit criteria độc lập; chi tiết phạm vi, dependency và phần phải thiết kế trước nằm trong phần **LeaseGate target architecture và phased delivery**.

## 17. Phân phối macOS

Vì ứng dụng có local daemon và CLI, first version nên ưu tiên bản signed/notarized phân phối trực tiếp. Mac App Store sandbox có thể làm helper process, persistent IPC và CLI integration phức tạp hơn.

Quyết định phân phối cần được xác nhận trong PRD, nhưng không ảnh hưởng tới domain model hoặc KDBX core.

## 18. Mở rộng thành universal secret vault

### Định hướng sản phẩm

Tương lai sản phẩm không chỉ quản lý account/password mà trở thành universal local secret vault cho cả người dùng, developer và agent.

Các nhóm secret có thể hỗ trợ:

| Nhóm | Secret kind |
|---|---|
| Cá nhân | Login, Credit Card, Identity, Passport, Secure Note, Recovery Codes |
| Developer | API Credential, SSH Key, Database Credential, Server, Certificate, Software License |
| Runtime | Environment Bundle, Service Credential, Webhook Secret, Signing Key |
| Khác | Document, Crypto Wallet, Wireless Router, custom user-defined kind |

Các password manager hiện đại cũng đi theo hướng typed items. 1Password có Login, Document, API Credential, Database, SSH Key, Server, Crypto Wallet và nhiều loại identity; Bitwarden có Login, Card, Identity, Secure Note và SSH Key. Tuy nhiên, typed item chủ yếu là schema và UX ở tầng ứng dụng, không nhất thiết phải là một file format riêng.

### Data model cần thiết kế ngay

Không hard-code domain thành một struct `Account` chỉ có username/password. Sử dụng model tổng quát:

```rust
pub struct VaultItem {
    pub id: ItemId,
    pub kind: ItemKindId,
    pub title: String,
    pub sections: Vec<ItemSection>,
    pub fields: Vec<ItemField>,
    pub urls: Vec<ItemUrl>,
    pub tags: Vec<String>,
    pub attachments: Vec<AttachmentRef>,
    pub notes: Option<SecretValue>,
    pub schema_version: u32,
    pub revision: u64,
}

pub struct ItemField {
    pub id: FieldId,
    pub key: String,
    pub label: String,
    pub value_type: FieldValueType,
    pub sensitivity: Sensitivity,
    pub value: FieldValue,
}
```

`kind` phải là identifier mở rộng được, ví dụ:

```text
core.login
core.api_credential
core.secure_note
core.ssh_key
core.database
core.environment
user.custom.<uuid>
```

Không dùng Rust enum đóng cho toàn bộ item kinds. Built-in kinds có typed schema, còn custom kinds được định nghĩa bằng template data.

`FieldValueType` có thể hỗ trợ:

- Text.
- Concealed text.
- URL.
- Email.
- Phone.
- Number.
- Date.
- Boolean.
- TOTP.
- Key pair.
- Certificate.
- File/attachment reference.
- Item/field reference.

`Sensitivity` tách khỏi `value_type`:

```text
public_metadata
private_metadata
secret
highly_sensitive
```

Ví dụ username có kiểu Text nhưng vẫn có thể được đánh dấu private. Private SSH key có kiểu Key Pair và mức highly sensitive.

### Kind chỉ là schema, không phải storage format

Một `ItemKindDefinition` nên định nghĩa:

- Các field mặc định.
- Field bắt buộc và optional.
- Label và section trong UI.
- Field nào dùng làm subtitle.
- Field nào dùng để match/autofill.
- Field nào agent được phép request.
- Validation rules.
- Suggested agent actions.

Ví dụ API Credential:

```json
{
  "kind": "core.api_credential",
  "fields": [
    {"key": "provider", "type": "text", "sensitivity": "public_metadata"},
    {"key": "account", "type": "text", "sensitivity": "private_metadata"},
    {"key": "credential", "type": "concealed", "sensitivity": "secret"},
    {"key": "hostname", "type": "url", "sensitivity": "public_metadata"}
  ]
}
```

### Ánh xạ universal model khi export KDBX

Mỗi secret kind được ánh xạ thành một KDBX Entry khi export:

- `Title`, `UserName`, `Password`, `URL`, `Notes` được dùng khi có semantic tương ứng.
- Các field khác được lưu thành KDBX custom string fields.
- Binary/document/private-key file có thể lưu dưới dạng attachment.
- `kind`, schema version, section layout và stable field IDs có thể lưu trong encrypted `Entry/CustomData` với namespace riêng, ví dụ `KeyLease.*`.
- Nếu một KeePass client không hiểu `kind`, người dùng vẫn thấy các field tiêu chuẩn và custom fields.
- Nếu app-specific metadata bị mất nhưng field values còn nguyên, app dùng fallback inference hoặc coi item là `core.generic` thay vì làm mất secret.

Agent authorization, client identity, grant và audit không được export vào KDBX. Export file sang máy khác không được vô tình mang theo quyền của agent hoặc cloud organization.

### Secret reference ổn định cho agent

Thiết kế ngay một URI không chứa plaintext:

```text
kl://<vault-id>/<item-id>/<field-id>
```

Ví dụ:

```text
kl://personal/019abc/credential
kl://work/019def/private_key
```

CLI và MCP tương lai dùng reference thay vì title/path có thể thay đổi:

```bash
keylease read 'kl://work/019abc/credential'
keylease run --env-file .env.keylease -- npm deploy
```

File `.env.keylease` chỉ chứa reference:

```dotenv
GITHUB_TOKEN=kl://work/019abc/credential
DATABASE_URL=kl://work/019def/connection_string
```

Việc resolve reference vẫn phải qua `keylease serve`, capability policy và audit. Reference tự nó không cấp quyền.

### Version và rotation metadata

Data model nên có chỗ cho metadata ngay từ first version, dù UI chưa sử dụng toàn bộ:

- `created_at` và `updated_at`.
- `secret_changed_at`.
- `expires_at`.
- `rotation_interval`.
- `last_used_at` nằm trong usage/audit store, không nằm trong encrypted item nếu không cần đồng bộ.
- `issuer/provider`.
- `environment`: development, staging, production.
- `owner` hoặc contact.
- `status`: active, expired, revoked, archived.

Không mutation encrypted item sau mỗi agent read vì sẽ gây sync writes và conflict không cần thiết. Usage/audit metadata nên nằm trong append-only event store riêng.

## 19. “Two secrets, one vault”

Trong mô hình của Keyfold, hai secret là:

1. Master password do người dùng nhớ.
2. Một Secret Key ngẫu nhiên, dài, được tạo trên thiết bị và lưu trong enrolled devices hoặc Emergency Kit.

Hai giá trị được kết hợp thông qua Argon2id và HKDF để tạo account unlock key. Ý tưởng là:

- Chỉ đánh cắp encrypted database từ server là chưa đủ.
- Chỉ biết master password là chưa đủ.
- Kẻ tấn công cần cả password và Secret Key.

Đây là mô hình đặc biệt có giá trị đối với cloud-hosted/zero-knowledge vault, vì server không nắm Secret Key ở dạng sử dụng được.

Trong KDBX, khái niệm gần nhất là composite master key gồm master password cộng với key file hoặc key-provider secret. Đặc tả KDBX hỗ trợ nhiều master-key components trước khi chạy KDF.

### Có nên áp dụng ngay không?

First version vẫn chỉ yêu cầu master password, nhưng key hierarchy phải được thiết kế ngay để thêm device/account Secret Key mà không re-encrypt toàn bộ items.

Không dùng password-derived key để mã hóa trực tiếp tất cả item. Thay vào đó:

1. Sinh ngẫu nhiên Account Root Key.
2. Mỗi vault và item có key ngẫu nhiên riêng.
3. Master password qua Argon2id tạo Password Unlock Key.
4. Password Unlock Key chỉ dùng để wrap/unwrap Account Root Key.
5. Sau này Device Secret, passkey hoặc recovery key trở thành các wrapping method bổ sung.

Đề xuất:

- First version local: chỉ expose master-password unlock trong UX.
- Thiết kế crypto envelope và key slots ngay từ first version.
- Trước cloud beta: thêm device-generated Secret Key và Emergency Kit nếu threat model chọn two-secret design.
- KDBX key file chỉ liên quan external KDBX compatibility, không dùng làm nền tảng cho native cloud vault.
- Quick unlock bằng Keychain/biometric là cơ chế tiện lợi để bảo vệ cached unlock material, không nên được mô tả như một second secret độc lập nếu threat model không chứng minh điều đó.

## 20. KDBX có phù hợp với agent era không?

### Kết luận

KDBX phù hợp làm **interoperability và portable export format**, nhưng không nên là canonical storage cho sản phẩm cloud/agent-first.

Nói cách khác:

```text
Native encrypted model       KDBX
--------------------------   -----------------------------
Canonical cloud data         Import/export
Per-item encryption          Portable migration
Sync revisions/tombstones    Strongbox/KeePass compatibility
Sharing/key wrapping         Offline compatibility backup
Agent grants/references      Optional external-vault mode
Typed extensible items
```

### Điểm mạnh của KDBX

- Format mở và portable.
- Được nhiều ứng dụng hỗ trợ.
- Có UUID ổn định cho entry/group.
- Có arbitrary custom string fields.
- Có attachments và history.
- Có encrypted custom data ở database/group/entry.
- Có integrity/authenticity checks.
- Hỗ trợ AES-256, ChaCha20 và Argon2id.
- Người dùng luôn có đường thoát qua Strongbox, KeePass hoặc KeePassXC.

### Giới hạn trong agent era

- File được mã hóa như một vault nguyên khối; không có per-item cryptographic access key.
- Unlock thường đưa toàn bộ cấu trúc vault vào process memory.
- Không có client identity hoặc agent identity.
- Không có field-level capability hay TTL grant.
- Không có approval workflow.
- Không có append-only audit log đáng tin cậy.
- Không có native secret-reference protocol.
- Không có lease, dynamic secret hoặc automatic rotation semantics.
- Không tối ưu cho concurrent fine-grained writes từ nhiều agent.
- Item kind/template không được chuẩn hóa xuyên suốt hệ sinh thái.
- Client không hiểu minor-version/custom metadata có thể bỏ qua dữ liệu; writer phải được kiểm thử lossless rất nghiêm ngặt.

`keylease serve` có thể che một phần giới hạn, nhưng KDBX nguyên khối vẫn làm sync, item-level sharing và key rotation phức tạp hơn cần thiết. Vì cloud là mục tiêu xác định, native model nên được chọn trước khi có dữ liệu production.

### Phương án storage được đề xuất

Áp dụng native encrypted object architecture:

```text
Account Root Key
  └── wraps Vault Keys
        └── each Vault Key wraps Item Keys
              ├── encrypted item payload
              └── encrypted attachment keys

Native local store
  encrypted items + revisions + tombstones + mutation log

Cloud server
  ciphertext objects + opaque IDs + sync metadata

Interoperability adapters
  KDBX + 1PUX import + CSV + CXF/CXP
```

Bitwarden công khai mô hình tương tự: mỗi item có một random Cipher Key riêng, sau đó key này được wrap bởi user hoặc organization key trước khi ciphertext được gửi lên server. Kiến trúc này thích hợp hơn cho rotation và sharing so với mã hóa toàn bộ vault trong một file nguyên khối.

Native local store có thể dùng SQLite cho index, revision và ciphertext blobs. SQLite không được chứa plaintext secret. Các device keys hoặc cached unlock material nhỏ được bảo vệ bằng OS Keychain.

### Cloud security invariants

- Mọi vault/item encryption diễn ra ở client.
- Server không nhận master password, account Secret Key, Account Root Key, Vault Key hoặc Item Key ở dạng plaintext.
- Authentication credential và vault-decryption key là hai mục đích khác nhau; dùng domain-separated derivation và không tái sử dụng cùng một key cho cả hai.
- Mỗi encrypted envelope chứa algorithm/version identifier để có crypto agility.
- Dùng AEAD với nonce đúng chuẩn; associated data phải bind ciphertext với account ID, vault ID, item ID, revision và schema version.
- Password change, device enrollment và recovery thao tác trên wrapped root keys thay vì giải mã/re-encrypt toàn bộ dữ liệu nếu không cần rotation.
- Thiết kế recovery trước cloud launch; không bổ sung recovery bằng một server-held master decryption key.
- Không tự thiết kế cryptographic primitive. Crypto design và implementation cần external security review trước khi chứa dữ liệu production.

### Sync model

- Server không giải mã item payload.
- Mỗi item có revision/version và tombstone riêng.
- Mutation có actor, device ID, base revision và idempotency key.
- Metadata nhạy cảm như title, URL, tags và field names cũng được mã hóa.
- Server chỉ giữ metadata tối thiểu cần cho authentication, rate limiting, billing và sync routing.
- Conflict text/metadata có thể three-way merge khi rõ ràng.
- Password, TOTP, private key và concealed fields không tự động merge; giữ conflict copies để người dùng quyết định.
- Attachments được chunk-encrypt bằng attachment key riêng.

### Native backup format

Cloud runtime storage không cần là một file duy nhất. Tuy nhiên sản phẩm cần một native encrypted backup format full-fidelity, versioned và self-contained. Backup này bảo toàn item kinds, key hierarchy, attachments và portable metadata nhưng không mang theo active sessions hoặc agent grants.

KDBX là compatibility export và sẽ có migration-loss report. Các feature như organization ownership, sharing policy, agent grants, audit, rotation state và một số passkeys không thể ánh xạ đầy đủ sang KDBX.

### Import/export với 1Password

- Import `.1pux` là khả thi vì 1Password công bố cấu trúc ZIP/JSON, sections, fields, history và attachments.
- `.1pux` là plaintext; import UI phải cảnh báo, tránh backup/indexing và đề nghị xóa an toàn sau import.
- Không dùng 1PUX làm native format hoặc encrypted backup.
- Không ưu tiên “Export to 1PUX”; format này có app-specific attributes và không được mã hóa.
- Để người dùng chuyển sang 1Password, export KDBX/CSV trong phạm vi phù hợp hoặc dùng platform Credential Exchange.
- Trên Apple platforms, chuẩn bị adapter cho AuthenticationServices Credential Exchange để trao đổi passwords và passkeys trực tiếp, không materialize plaintext CSV.

### Quyết định sản phẩm

- Native vault là default và là loại vault duy nhất được cloud-sync.
- KDBX import/export là first-class feature.
- External KDBX open-in-place là optional compatibility mode.
- Không sync một external KDBX đồng thời bằng native object sync engine.
- Không hứa round-trip KDBX cho các native-only features; luôn hiển thị export-loss report.

## 21. Những phần cần thiết kế trước và phần có thể hoãn

### Thiết kế ngay trong first version

- Generic `VaultItem`, không dùng model `Account` đóng.
- Extensible `kind` và versioned kind schema.
- Stable item ID và field ID.
- Ordered fields và sections.
- Sensitivity độc lập với field type.
- Account/Vault/Item key hierarchy và versioned crypto envelope.
- Random per-item keys; master password chỉ unwrap root key.
- Native encrypted object schema.
- Revision, tombstone và mutation-log schema sẵn sàng cho sync.
- Native encrypted full-fidelity backup format.
- KDBX import/export mapping contract và loss report.
- 1PUX import mapping contract.
- Extension bag để giữ source metadata không ánh xạ trực tiếp được.
- Stable secret-reference URI.
- Actor context và field-level capability.
- Revision, idempotency và atomic mutation.
- Repository/import/export adapter boundaries.
- Tách encrypted item data khỏi local/cloud control metadata.
- Stable connection ID, connector version và authentication-method model.
- Canonical action/resource model cho file, document, spreadsheet, repository, workspace, team và page.
- Response policy gồm item/cell/byte budget, content access level và untrusted-content marker.
- Connector credential lifecycle tách khỏi access lease và agent client credential.

### Implement trong first version

- Login.
- API Credential.
- Secure Note.
- Generic/custom item.
- Custom fields.
- TOTP.
- Native local encrypted store.
- KDBX import và KDBX export.
- 1PUX import nếu effort cho phép; nếu không, giữ adapter contract và fixtures trong technical spike.
- Agent CLI read/write theo capability.
- LeaseGate local PEP, opaque execution lease, exact-request approval, revoke, kill switch và audit.
- Fake Connector và connector conformance suite.
- Google Workspace Connector production cho selected Drive files, Docs và bounded Sheets ranges.
- GitHub public beta cho repository/issue/pull-request actions giới hạn.
- Linear private beta cho issue/comment actions.
- Notion private beta cho page actions trên content đã share với connection.

### Thiết kế schema nhưng hoãn UI/integration chuyên biệt

- SSH Key và SSH agent.
- Database Credential.
- Environment Bundle và secret injection.
- Certificate/key pair.
- Recovery Codes.
- Credit Card và Identity.
- Document/attachment editing.
- Rotation workflow.

### Hoãn hoàn toàn

- Cloud service implementation, nhưng không hoãn sync/key design.
- Device Secret/Emergency Kit UX; crypto envelope phải có key slots từ đầu.
- Team sharing.
- Dynamic secrets.
- External KDBX open-in-place nếu không cần cho initial migration UX.

## 22. Rust CLI độc lập và triển khai trên VPS

### Kết luận

First version phải có một Rust CLI chạy độc lập trên macOS và Linux/VPS, không phụ thuộc Flutter, Swift hoặc GUI.

Nên phát hành một binary chính:

```text
keylease
```

Binary có hai execution modes:

```text
Desktop mode
  keylease CLI ── Unix socket ── keylease serve
                                  └── native encrypted store

Standalone VPS mode
  keylease command
      └── Rust Vault Service chạy in-process
            └── native encrypted store
```

Cũng có thể dùng cùng binary để chạy daemon:

```bash
keylease serve --socket /run/user/<uid>/keylease.sock
```

Không bắt buộc phát hành hai executable `keylease` và `keyleased`; một binary với subcommand `serve` giúp cài đặt và versioning đơn giản hơn.

### Nguyên tắc đóng gói

- `vault-domain`, `vault-crypto`, `native-store`, `vault-commands` và `vault-policy` là pure Rust crates hỗ trợ macOS/Linux.
- Flutter chỉ là presentation client.
- Swift/Keychain/security-scoped bookmark nằm sau platform traits và không được trở thành dependency của CLI Linux.
- KDBX/1PUX importers là optional Cargo features nếu cần giảm binary size.
- Linux release nên có artifact cho `x86_64` và `aarch64`.
- Schema và encrypted store phải tương thích giữa desktop CLI, VPS CLI và cloud client.

### CLI trên VPS với master password

First version chỉ hỗ trợ master-password unlock nên có hai cách dùng an toàn:

1. Interactive command đọc password trực tiếp từ TTY.
2. Người dùng unlock một daemon session có TTL, sau đó agent dùng CLI qua Unix socket trong thời gian session còn hiệu lực.

Ví dụ:

```bash
keylease vault unlock work
keylease serve --session-ttl 8h
keylease item create --input-json -
keylease vault lock work
```

Không hỗ trợ:

```bash
keylease unlock --password 'secret'
KEYLEASE_PASSWORD=secret keylease unlock
```

Master password không được đưa vào process arguments, shell history, environment, config file hoặc agent prompt/context.

### Giới hạn automation trong first version

Master-password-only không thể đồng thời cung cấp unattended unlock an toàn sau khi VPS reboot. First version phải chọn một trong hai trạng thái:

- Có người unlock qua TTY và cấp session TTL; agent hoạt động sau đó.
- Vault vẫn locked và agent nhận `requires_user_action`.

Không âm thầm giải quyết bằng cách lưu master password plaintext trên VPS.

Unattended workloads là feature sau MVP, dùng một trong các cơ chế:

- Device/service key được wrap vào Account Root Key.
- OS keyring hoặc systemd credentials khi threat model cho phép.
- Cloud service account có quyền vào một vault/project giới hạn.
- Short-lived workload identity đổi lấy scoped secret lease.

### VPS process boundary

Nếu nhiều agent/process cùng dùng vault, chạy daemon mode để có một writer duy nhất. Unix socket phải:

- Có permissions `0600` mặc định.
- Kiểm tra peer UID trên platform hỗ trợ.
- Bắt buộc client registration/capability ngoài kiểm tra UID.
- Rate-limit sensitive operations.
- Thu hồi mọi session/grant khi vault lock.

Nếu agent có arbitrary shell dưới cùng Unix user với daemon, UID/socket permissions không phải security boundary đủ mạnh. Nên chạy agent dưới Unix user riêng hoặc container riêng và cấp client key/capability giới hạn.

### First-version VPS acceptance criteria

- CLI chạy headless trên Linux không cài Flutter.
- Init/unlock/lock/search/read/create/update/delete hoạt động bằng JSON contract.
- Connection/lease/gate commands dùng cùng schema và policy decision như desktop.
- Connector action đã enroll có thể chạy headless mà không trả upstream credential qua stdout hoặc process arguments.
- Interactive password chỉ đọc từ TTY và không echo.
- Daemon session sống qua nhiều CLI invocations nhưng hết hạn đúng TTL.
- Concurrent writers không làm hỏng local encrypted store.
- Agent ngoài capability bị từ chối ở service layer.
- Crash/restart không để lại plaintext hoặc partial transaction.
- Export KDBX từ VPS mở được bằng Strongbox/KeePassXC.

## 23. Product naming và LeaseGate

### Hệ thống tên

- **KeyLease** là tên sản phẩm và thương hiệu tổng thể.
- **KeyLease Vault** là encrypted secret store local/native.
- **KeyLease CLI** là Rust CLI với binary `keylease`.
- **KeyLease Cloud** là control plane cho identity, policy, approval, audit và organization.
- **LeaseGate** là access gateway cấp quyền tạm thời cho agent.
- **KeyLease Connectors** kết nối LeaseGate tới Google Workspace, GitHub, Linear, Notion, cloud providers, database, SSH và external services.

Tagline cấp sản phẩm:

> **KeyLease — Secure secrets. Lease access.**

Thông điệp dành cho agent:

> **LeaseGate — Give agents access, not secrets.**

KeyLease "lease access", không gửi raw key hoặc long-lived secret cho agent. Tên `KeyLease` là product metaphor; API và domain language không được tạo cảm giác private key thật luôn được trao ra ngoài.

### LeaseGate không chỉ là một cloud endpoint

LeaseGate được phát hành đầu tiên như một capability của KeyLease Cloud, nhưng enforcement engine phải chạy được ở nhiều placement:

```text
KeyLease Cloud
  ├── identity, policy, approvals và audit control plane
  └── LeaseGate Cloud

Customer VPS/VPC/device
  └── LeaseGate Edge/self-hosted
       └── local database, SSH và private APIs
```

Điều này cho phép enterprise giữ long-lived secrets và connector gần workload. Cloud có thể phân phối signed policy và nhận audit events mà không cần nhận plaintext secret.

### Access lease thay cho "session key"

Không dùng `session key` làm domain term vì thuật ngữ này thường chỉ cryptographic key dùng để mã hóa một session.

Chuẩn hóa các khái niệm:

| Thuật ngữ | Ý nghĩa |
|---|---|
| `Secret` | Credential/key thực được mã hóa trong vault |
| `Lease Policy` | Điều kiện để một agent/workload được sử dụng resource |
| `Access Lease` | Quyền tạm thời đã được cấp |
| `Lease Token` | Opaque credential mà agent trình cho LeaseGate |
| `Connector` | Adapter thực hiện exchange, proxy hoặc action downstream |
| `LeaseGate` | Policy enforcement point kiểm tra từng request |

Một access lease tối thiểu phải bind:

- Subject: agent, workload và khi có thể là human principal đã ủy quyền.
- Resource và environment cụ thể.
- Action cụ thể, không chỉ read/write chung chung.
- Audience/connector đích.
- Content-access level và item/cell/byte response budget nếu action trả external data.
- TTL ngắn và thời điểm hết hạn tuyệt đối.
- Maximum uses hoặc rate limit khi phù hợp.
- Policy version, approval context và task correlation ID.
- Cơ chế revoke; có thể bổ sung proof-of-possession để giảm rủi ro bearer-token theft.

Ví dụ response không chứa secret gốc:

```json
{
  "lease_id": "lease_01K...",
  "token": "kl_live_...",
  "resource": "github:repo/acme/api",
  "actions": ["github.issue.create"],
  "expires_in": 600,
  "max_uses": 3
}
```

### Ba chiến lược connector

1. **Credential exchange:** nếu provider hỗ trợ AWS STS, OAuth token exchange, SSH certificate hoặc cơ chế tương đương, connector sinh credential native có TTL ngắn.
2. **Gateway proxy:** nếu provider chỉ hỗ trợ static API key, LeaseGate giữ key và thực hiện request thay agent; agent chỉ thấy lease token.
3. **Process injection:** với tool local, KeyLease inject secret vào memory/environment của child process trong thời gian chạy, không đưa secret vào model context, arguments, persistent file hoặc log.

Không thể tự thay một static upstream credential bằng temporary token nếu upstream không hiểu token đó. Khi ấy agent phải gọi qua LeaseGate hoặc connector phải thực hiện action thay agent.

### API và CLI direction

```bash
keylease lease request \
  --resource github:repo/acme/api \
  --action github.issue.create \
  --ttl 10m

keylease gate execute \
  --lease lease_01K... \
  --action github.issue.create \
  --input-json -
```

CLI, MCP và SDK chỉ là các transport adapters trên cùng policy engine:

```text
KeyLease CLI ─┐
MCP adapter ──┼── LeaseGate policy/enforcement ── Connectors
KeyLease SDK ─┘
```

MCP không phải security boundary. LeaseGate phải xác thực identity, lease, scope và concrete action arguments trên mỗi request, bất kể request đến từ CLI, MCP hay SDK.

### Naming kỹ thuật đề xuất

```text
Binary:              keylease
Local daemon:        keylease serve
Secret reference:    kl://<vault>/<item>/<field>
Lease token prefix:  kl_live_
Lease ID prefix:     lease_

Rust crates:
  keylease-core
  keylease-cli
  keylease-store
  keylease-kdbx
  leasegate-policy
  leasegate-connectors
```

Tên và prefixes là working conventions; phải thực hiện domain, package registry và trademark clearance trước public launch.

## 24. LeaseGate target architecture và phased delivery

### Product thesis

LeaseGate là credential broker và policy enforcement gateway cho agent. Người dùng kết nối account/service một lần; agent chỉ nhận một endpoint hoặc lease token bị giới hạn theo identity, resource, action, arguments, thời gian và ngân sách.

```text
Long-lived secret/OAuth connection
              │
              ▼
        KeyLease Vault
              │ không reveal mặc định
              ▼
          LeaseGate
              │ short-lived, scoped access
              ▼
            Agent
```

North-star outcome:

> Một agent bị prompt injection hoặc bị chiếm quyền vẫn không thể đọc dữ liệu hoặc hành động vượt quá lease cụ thể đã được cấp.

LeaseGate giảm blast radius; nó không làm model trở nên đáng tin và không thay thế sandbox, workload isolation hoặc authorization của downstream service.

### Capability baseline của LeaseGate

LeaseGate phải cung cấp baseline của một agent access gateway:

- Connect external service bằng OAuth một lần.
- Tạo identity/endpoint riêng cho từng agent.
- Default deny và bật quyền theo từng action/tool.
- Proxy MCP request và enforce trước khi forward.
- Rate limit theo endpoint.
- Audit mỗi tool call.
- Revocation ngay tại gateway mà không revoke OAuth connection gốc.
- Cloud và self-hosted dùng cùng core behavior.

LeaseGate không dừng ở permission matrix. Định hướng đầy đủ của KeyLease:

| Dimension | Gateway baseline | LeaseGate direction |
|---|---|---|
| Entry point | MCP endpoint | CLI, MCP, SDK, HTTP/gRPC cùng policy core |
| Authorization | Per-agent/per-action | Per-request: subject + resource + action + typed arguments + context |
| Lifetime | Endpoint key cho đến khi revoke | Access lease ngắn hạn, max-use và instant revoke |
| Secret source | Connected OAuth/service token | Native KeyLease Vault, imports và external secret providers |
| Execution | Hosted/self-hosted proxy | Cloud, edge/VPC hoặc local process boundary |
| Credential delivery | Proxy token | Proxy action, token exchange, dynamic credential hoặc process injection |
| Human control | Static configuration | Risk-based approval bind với exact request |
| Lifecycle | Access proxy | Secret lifecycle, expiry, rotation và usage feedback |

### Trust modes phải công khai và tách biệt

Không thể gọi mọi deployment là zero-knowledge. Nếu hosted LeaseGate cần dùng OAuth refresh token hoặc API key để proxy request, service runtime phải có khả năng sử dụng credential đó.

KeyLease định nghĩa hai trust modes:

1. **Zero-knowledge vault + Edge execution:** cloud chỉ giữ ciphertext, policy metadata cần thiết và audit đã redact. KeyLease/LeaseGate Edge trong device, VPS hoặc VPC của khách hàng unwrap secret và gọi downstream.
2. **Managed gateway opt-in:** LeaseGate Cloud giữ credential được mã hóa at rest và unwrap trong isolated runtime/HSM-backed boundary để gọi downstream. Đây là managed-secrets mode, không quảng cáo là zero-knowledge cho các connection đó.

Mỗi connection phải hiển thị rõ execution location và trust mode trong UI/API. Không silently chuyển từ Edge sang Managed khi Edge offline.

First-version connectors chỉ chạy ở local/Edge trust mode. OAuth refresh token, internal integration token và API credential được mã hóa trong local vault; managed connector execution vẫn ngoài phạm vi MVP.

### Target architecture

```text
                         KEYLEASE CLOUD CONTROL PLANE
┌─────────────────────────────────────────────────────────────────────┐
│ Org / Project / Human Identity / Agent Registry                    │
│ Connection metadata / Policy versions / Approval workflow          │
│ Lease issuer / Revocation state / Audit index / Risk configuration │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ signed policy + control events
                            │ redacted/signed audit events
              ┌─────────────┴─────────────┐
              ▼                           ▼
       LEASEGATE CLOUD              LEASEGATE EDGE
       managed opt-in               device / VPS / VPC
┌───────────────────────┐      ┌────────────────────────┐
│ Transport adapters    │      │ Transport adapters     │
│ PEP + policy cache    │      │ PEP + policy cache     │
│ Lease validation      │      │ Lease validation       │
│ Connector runtime     │      │ Connector runtime      │
│ Audit spool           │      │ Local vault access     │
└──────────┬────────────┘      └───────────┬────────────┘
           │                               │
           └──────────────┬────────────────┘
                          ▼
       Google Workspace / GitHub / Linear / Notion / AWS / DB / SSH / APIs
```

Control plane không nằm trên hot path bắt buộc của mọi Edge request. Edge phải dùng signed, versioned policy cache và revocation feed có thời hạn. Khi mất kết nối cloud:

- Expired policy/lease luôn fail closed.
- High-risk action fail closed.
- Có thể cho phép low-risk action trong bounded offline window do policy quy định.
- Audit được spool mã hóa cục bộ và upload khi reconnect.

### Logical components cần ổn định từ đầu

- **Identity Registry:** human, agent, workload, device và service account.
- **Connection Registry:** provider, owner, auth method, trust mode, execution location và health.
- **Tool/Action Catalog:** typed action schemas độc lập với MCP transport.
- **Policy Decision Point (PDP):** quyết định allow, deny hoặc require approval.
- **Policy Enforcement Point (PEP):** canonicalize request, gọi PDP và chặn trước side effect.
- **Lease Issuer/Validator:** issue, introspect, consume, expire và revoke lease.
- **Approval Service:** bind approval với canonical request digest.
- **Connector Runtime:** OAuth refresh, token exchange, proxy và response filtering.
- **Audit Pipeline:** append, redact, sign/hash, spool, query và export.
- **Risk Engine:** deterministic rules và budgets; ML chỉ được đưa ra recommendation.
- **Transport Adapters:** CLI, MCP, SDK, HTTP/gRPC.

Không cho transport adapter tự implement authorization. Mọi transport phải tạo cùng một canonical `ActionRequest`.

### Identity và delegation chain

Không gộp agent identity với endpoint API key. Data model cần phân biệt:

- `human_principal`: người sở hữu hoặc phê duyệt.
- `agent`: logical agent như `deploy-bot`.
- `workload_instance`: process/container/VM cụ thể đang chạy agent.
- `client_session`: kết nối hiện tại.
- `task`: intent/task cụ thể có deadline.
- `on_behalf_of`: delegation chain từ người hoặc service sang agent.

Ví dụ:

```text
human:alice
  └── agent:deploy-bot
       └── workload:spiffe://acme/prod/deploy-bot
            └── task:release-2026-09-05
```

MVP local có thể dùng registered client key + Unix peer credentials. Cloud/enterprise bổ sung OIDC, mTLS và SPIFFE/SPIRE workload attestation. Network location hoặc Unix UID đơn lẻ không phải identity đủ mạnh.

### Canonical action model

Policy phải áp dụng lên action có schema, không áp dụng trực tiếp lên raw MCP JSON hoặc arbitrary HTTP request:

```json
{
  "request_id": "req_01K...",
  "subject": {
    "agent_id": "agent_deploy",
    "workload_id": "spiffe://acme/prod/deploy-bot",
    "on_behalf_of": "human_alice"
  },
  "task_id": "release-2026-09-05",
  "connection_id": "conn_github_acme",
  "resource": "github:repo/acme/api",
  "action": "github.pull_request.create_draft",
  "arguments": {
    "base": "main",
    "head": "release/1.4",
    "draft": true
  },
  "idempotency_key": "release-1.4-pr"
}
```

Connector phải canonicalize alias, Unicode, path, URL, repository identity và provider-specific IDs trước policy evaluation. Authorization luôn chạy lại sau canonicalization để tránh scope bypass.

### Policy model

Policy rule tối thiểu gồm:

```text
effect        deny | allow | require_approval
subject       agent/workload/on-behalf-of selectors
connection    exact connection hoặc provider class
resource      exact ID, hierarchy hoặc constrained pattern
action        typed action name
arguments     typed constraints/allowlists/ranges
context       environment, task, time window, device posture
budget        rate, count, bytes, money hoặc rows affected
validity      not-before, expiry, max lease TTL
approval      approver set, quorum, reason và expiry
```

Nguyên tắc:

- Default deny và explicit deny thắng allow.
- Policy deterministic, versioned và testable.
- Authorization error hoặc unknown field phải fail closed.
- Không dùng LLM làm PDP hoặc judge cuối cùng.
- LLM có thể đề xuất policy; người dùng hoặc deterministic guard phải chấp nhận.
- Policy template giúp onboarding, nhưng grant thực tế phải materialize thành rule rõ ràng.
- Policy simulation/dry-run phải cho biết rule nào match và vì sao deny mà không lộ secret.

Không chỉ kiểm tra tool name. Ví dụ `github.issue.create` được phép nhưng owner/repo, labels và target URL vẫn phải nằm trong allowlist.

### Risk tiers và approval

| Tier | Ví dụ | Default behavior |
|---|---|---|
| R0 | health/status, public metadata | Lease dài hơn, không approval |
| R1 | đọc resource giới hạn | Grant có TTL và audit |
| R2 | write có thể reverse | Short lease, idempotency bắt buộc |
| R3 | external communication/deploy | Approval theo policy hoặc pre-approved task |
| R4 | delete, IAM, money, secret reveal | Per-action approval hoặc deny |

Approval phải bind với hash của canonical request gồm action, resource, material arguments, subject, policy version và expiry. Nếu agent thay đổi arguments sau approval, request mới phải được đánh giá/approve lại.

Approval states:

```text
pending → approved → consumed
        ↘ denied
        ↘ expired
approved → revoked
```

`execute_on_approval` có thể queue exact request để tránh agent polling và tránh time-of-check/time-of-use drift. Approval UI phải hiển thị semantic diff và blast radius, không chỉ JSON thô.

### Access lease lifecycle

```text
1. Authenticate subject/workload
2. Parse + validate typed action
3. Canonicalize resource and arguments
4. Evaluate policy and budgets
5. Request approval if required
6. Issue opaque or sender-constrained lease
7. Re-evaluate mutable constraints on every use
8. Execute through connector
9. Filter/redact response
10. Commit usage counter + audit outcome
11. Expire or revoke
```

Lease types:

- **Execution lease:** một exact action, ưu tiên cho destructive/high-risk operations.
- **Capability lease:** nhiều action trong bounded resource set và TTL.
- **Data lease:** đọc exact external resources với content level, item/cell/byte budget và response filtering.
- **Credential lease:** downstream-native short-lived credential khi provider hỗ trợ.
- **Process lease:** inject secret vào một child process có lifecycle kiểm soát.

Không phát hành offline-verifiable token dài hạn chỉ để giảm lookup. MVP dùng opaque random token + server-side state để revoke chính xác. Sau này có thể dùng signed token TTL rất ngắn kết hợp revocation epoch và proof-of-possession.

### Connector contract

Mỗi connector khai báo:

- Provider và version.
- Authentication methods, OAuth/public-client constraints và connection lifecycle.
- Actions cùng JSON Schema/typed schema.
- Resource hierarchy và canonicalization rules.
- Required upstream permissions.
- Risk tier mặc định cho từng action.
- Argument validators và response redaction schema.
- Response data policy gồm item/cell/byte limits, MIME types và content-access level.
- Provenance và marker cho external content phải được xem là untrusted.
- Idempotency behavior.
- Hỗ trợ proxy, exchange, dynamic credential hoặc process injection.
- Health check, refresh/rotation và revoke behavior.
- Audit-safe fields; trường nào phải hash, redact hoặc bỏ hoàn toàn.

Không dựa vào string filtering cho hành động quan trọng. Ví dụ database read-only cần database role read-only, query parser/AST và transaction guard; tìm chuỗi `DELETE` là không đủ.

Connector runtime phải có outbound allowlist, DNS/IP revalidation, timeout, response-size limit và SSRF defense. Custom connector chạy trong sandbox/process boundary riêng.

### Data-returning connector

Google Drive, Docs, Sheets, Linear và Notion không chỉ dùng credential để thực hiện side effect; chúng còn trả user/workspace data về agent. Với nhóm connector này, access lease phải bind thêm:

- Exact resource IDs và hierarchy đã được người dùng chọn.
- `content_access`: metadata, bounded content hoặc full selected resource.
- `max_items`, `max_cells` và `max_response_bytes` khi phù hợp.
- Allowed MIME types, ranges hoặc field projections.
- Expected revision/value digest cho mutation cần optimistic conflict detection.
- Data classification và `untrusted_content` marker.

Response phải kèm provider, connection ID, canonical resource ID và revision/ETag khi có. Agent host phải xem nội dung bên ngoài là data không đáng tin, không phải instruction có quyền thay đổi policy. Audit không ghi raw document, issue body, page text hoặc cell values trừ khi một compliance mode riêng được thiết kế với encryption và retention tách biệt.

### MCP gateway behavior

MCP là một transport quan trọng, không phải domain model:

- Một endpoint/credential riêng cho từng agent hoặc workload.
- Tool discovery chỉ hiển thị tools agent có khả năng request; enforcement vẫn bắt buộc khi call.
- Map MCP tool + arguments sang canonical action.
- Không forward unknown tool/schema version.
- Preserve request/correlation ID và idempotency key.
- Trả structured `denied`, `approval_required`, `lease_expired` và `requires_user_action`.
- Không cho MCP tool unlock vault, export plaintext, tắt audit hoặc thay policy trực tiếp.
- Agent chỉ được propose policy change; human/admin mới activate.

### Audit, privacy và observability

Audit event phải trả lời được: ai/agent/workload nào, thay mặt ai, dùng policy version nào, request action/resource gì, decision nào, connector nào thực thi và outcome gì.

Không log raw secret hoặc full response. Với arguments nhạy cảm:

- Redact hoàn toàn khi không cần điều tra.
- Hash/HMAC stable identifier khi cần correlation.
- Encrypt restricted audit payload bằng key/retention riêng nếu compliance bắt buộc.

Audit local dùng append-only event store. Cloud/enterprise thêm hash chain/signature, immutable export, retention policy, SIEM/webhook và anomaly alerts. Audit integrity không được dựa chỉ vào cùng database/admin boundary với application state.

### Kill switch, budgets và abuse controls

LeaseGate cần revoke ở nhiều cấp:

- Một lease.
- Một task/session.
- Một workload instance.
- Một logical agent.
- Một connection/provider.
- Một project hoặc organization.
- Global emergency stop cho mọi side-effecting action.

Budgets là phần của authorization, không chỉ monitoring:

- Requests/time window.
- Rows/objects/bytes read hoặc changed.
- Recipients/messages/files created.
- Monetary amount per action/day.
- Concurrent executions.
- Cumulative task budget.

Counter update phải atomic với permission decision hoặc dùng reservation để concurrent calls không vượt trần.

### Những gì cần thiết kế từ Phase 0

Phải ổn định về concept và có version field ngay từ đầu:

- IDs cho org/project/human/agent/workload/task/connection/action/lease.
- Canonical `ActionRequest`, `PolicyDecision` và `AuditEvent`.
- Typed action catalog và connector trait.
- Policy precedence, default deny và approval binding.
- Lease lifecycle, revocation semantics và clock-skew rules.
- Idempotency, budgets và concurrency semantics.
- Edge/cloud placement cùng trust-mode metadata.
- Secret/reference URI không phụ thuộc transport.
- Error taxonomy cho CLI, MCP và API.
- Crypto/key hierarchy cho E2EE vault và managed connector credentials.

Chưa cần implement đầy đủ ở Phase 0:

- Policy language phức tạp hoặc third-party engine.
- Hàng chục connectors.
- SPIFFE, SCIM, SIEM và enterprise federation.
- Machine-learning anomaly detection.
- Hosted managed gateway.

Thiết kế internal policy IR ổn định trước; adapter tới Cedar/OPA hoặc engine khác có thể quyết định sau benchmark.

### Phased delivery và exit criteria

#### Phase 0 — Foundation contracts

Deliverables:

- Threat model gồm prompt injection, confused deputy, token theft, malicious connector, SSRF, replay và compromised cloud/edge.
- Versioned domain schemas và Rust traits cho policy, lease, connector, action và audit.
- Golden policy test vectors và deny-by-default conformance suite.
- Crypto/key hierarchy spike và cloud/edge trust boundary ADR.
- Sync simulation và canonicalization adversarial tests.

Exit criteria: Fake Connector chạy end-to-end qua cùng `ActionRequest`; mô phỏng OAuth expiry/revoke, pagination, rate limit, timeout, schema drift, canonicalization attack, replay và concurrent side effects; deny unknown action/field; approval bind exact request; audit không chứa fixture secrets hoặc external content.

#### Phase 1 — KeyLease + LeaseGate Local MVP

Ship:

- macOS Flutter app và Rust CLI/headless Linux.
- Native encrypted vault, master-password unlock và atomic storage.
- Account, custom fields, TOTP, groups, search và history cơ bản.
- KDBX import/export có migration report.
- Agent registration, scoped local grant và write với revision/idempotency.
- `keylease serve` hoạt động như local PEP và connector runtime.
- Opaque execution lease có TTL, `max_uses`, exact-request approval, revoke và kill switch.
- Connection Registry cùng encrypted OAuth/API-token lifecycle.
- Typed action/resource policy, response data budgets và untrusted-content marker.
- Fake Connector và shared connector conformance suite.
- Google Workspace Connector production gồm selected Drive files, Docs và bounded Sheets ranges.
- GitHub public beta; Linear và Notion private beta theo phạm vi action đã định.
- CLI `connection`, `lease request`, `gate execute` và `audit query`.

Exit criteria: dùng KeyLease hàng ngày cho phạm vi vault MVP; export KDBX mở được bằng Strongbox/KeePassXC; CLI agent write không bypass policy/audit; người dùng chọn Google files qua Picker và agent có thể đọc một Doc, append/update một bounded Sheet range mà không nhận Google credential; spreadsheet/range/action ngoài scope bị deny; formula write, sharing và delete không tồn tại; approval argument change, retry, restart và concurrency không vượt lease budget hoặc tạo side effect trùng. GitHub, Linear và Notion beta phải pass deny-by-default, token-redaction và resource-scope conformance nhưng chưa là launch blocker về availability SLO.

#### Phase 2 — Connector hardening và LeaseGate Local Alpha

Ship:

- Production hardening cho GitHub, Linear và Notion theo usage telemetry.
- OAuth refresh/revocation recovery, incremental reauthorization và connection health UX.
- Deterministic policy templates theo agent/resource/action/typed arguments cho từng provider.
- Advanced local approval queue, task-bound approvals và semantic diff cho external writes.
- Read/write budgets theo item, cell, byte và task; atomic reservations cho concurrent calls.
- Connector-specific idempotency journals, reconciliation và partial-failure recovery.
- Adversarial conformance cho provider schema changes, aliases, pagination và rate limits.

Exit criteria: agent tạo GitHub issue/draft PR, Linear issue/comment và Notion page update qua gateway mà không nhận upstream token; unauthorized repository/workspace/team/page/action/arguments bị deny; mọi production connector pass conformance suite; refresh/revoke failures fail closed; restart/replay/concurrency không vượt lease hoặc data budget.

#### Phase 3 — KeyLease Cloud + LeaseGate Edge/MCP Beta

Ship:

- Account, organization, project, membership và agent registry.
- E2EE vault sync trên native object/revision protocol.
- Cloud policy/approval control plane và signed versioned policy distribution.
- LeaseGate Edge cho Linux VPS/VPC với encrypted audit spool.
- Streamable HTTP MCP endpoint tối thiểu, credential riêng cho từng agent và map tool call sang canonical action.
- Remote approval/revocation từ web; mobile web đủ dùng.
- Edge health, connector health và revocation feed.

Exit criteria: cloud không thể decrypt zero-knowledge vault; cùng action qua CLI và MCP nhận cùng policy decision; Edge mất mạng vẫn tuân bounded offline policy; revoke cloud có bounded propagation SLO và fail-closed khi state quá hạn.

#### Phase 4 — Connector platform và policy UX

Ship:

- MCP tool discovery filtering + per-call enforcement đầy đủ.
- Visual permission matrix, policy templates và simulation.
- OAuth connection onboarding/refresh cho additional providers và public one-click Notion connection.
- Rate limits/budgets, audit explorer và connector SDK/schema registry.
- Agent propose-policy flow; human activate.

Exit criteria: một MCP client phổ biến connect trong vài phút; cùng policy cho kết quả giống CLI; endpoint revoke không làm mất OAuth connection gốc; connector conformance suite chặn schema/canonicalization bypass.

#### Phase 5 — Dynamic credentials và self-hosted local Gateway

> Quyết định phạm vi 2026-09-06: Phase 5 chỉ ship
> `self_hosted/local_gateway` all-in-one trên VPS của người dùng. “Cloud” là
> Control Plane chạy cùng VPS, không phải hạ tầng do LeaseGate vận hành.
> LeaseGate-hosted Managed Gateway được loại khỏi runtime và phải bị reject nếu
> cấu hình nhầm.

Ship:

- OAuth 2.0 Token Exchange khi provider hỗ trợ.
- AWS/cloud short-lived credentials, SSH certificates và database leases.
- Local Gateway thực thi trên VPS của người dùng; credential/key không đi vào Control Plane.
- Sender-constrained lease bằng DPoP/mTLS nơi phù hợp.
- Secret rotation workflow, expiry alerts và connection posture.

Exit criteria: agent workflows trọng tâm không dùng long-lived downstream credentials; API/UI/config chỉ chấp nhận rõ `self_hosted/local_gateway`; credential không đi vào Control Plane; token theft tests chứng minh sender constraint tại các flow hỗ trợ.

#### Phase 6 — Enterprise và mobile

> Quyết định phạm vi 2026-09-06: Phase 6 tiếp tục mô hình
> `self_hosted/local_gateway`. Self-hosted Control Plane đã ship ở Phase 5;
> Phase 6 tập trung hardening, enterprise identity, mobile approval,
> policy-as-code, compliance và HA primitives. Không thêm vendor-managed path.

Ship:

- iOS/Android app cho vault, approval, revoke và security alerts.
- SSO/OIDC, SCIM, role separation và access reviews.
- SIEM export, retention controls, tamper-evident audit và compliance evidence.
- HA Edge, self-hosted control plane, BYOK/HSM và workload identity federation.
- Policy-as-code, signed bundles, staged rollout và rollback.

Exit criteria: multi-region/HA failure tests, separated-admin threat tests và external security review hoàn tất cho enterprise launch.

### Product metrics theo phase

Không tối ưu chỉ theo số connector. Theo dõi:

- Tỷ lệ agent actions không cần reveal raw secret.
- Median lease TTL và tỷ lệ lease hết hạn không được dùng.
- Số deny đúng, approval rate và time-to-approve.
- Permission utilization: quyền được cấp nhưng không dùng.
- Revocation propagation latency.
- Connector error/refresh failure rate.
- Tỷ lệ data reads bind với exact file/page/sheet/range thay vì broad account scope.
- Số request bị chặn do vượt item/cell/byte budget hoặc resource scope.
- Số secret xuất hiện trong logs/model context: mục tiêu bằng 0.
- Thời gian từ connect service đến successful bounded action đầu tiên.

### Non-goals dài hạn

- Không trở thành general-purpose LLM firewall hoặc prompt-injection detector.
- Không tin model tự khai báo intent/action để authorize.
- Không thay thế sandbox/container isolation.
- Không hứa raw secret sẽ không thể bị exfiltrate nếu người dùng cố ý cấp `reveal_secret` hoặc full process control.
- Không yêu cầu mọi integration phải dùng MCP.
- Không đồng nhất encrypted-at-rest managed connector với zero-knowledge vault.
