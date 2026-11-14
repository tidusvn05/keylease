# KeyLease v2: kế hoạch thiết kế lại nền tảng (bản nháp)

Trạng thái: **nháp để thảo luận**, chưa phải ADR. Ngày: 2026-11-14.
Phạm vi: đặt lại tên, cấu trúc sản phẩm, mô hình dữ liệu, kiến trúc server
self-hosted và lộ trình refactor. Khi chốt, từng phần sẽ tách thành ADR riêng
(tiếng Anh) như các ADR hiện có.

---

## 0. Mục tiêu và nguyên tắc

**Mục tiêu:** một *trust layer cho agent*: agent dùng được credential mà model
không thấy, con người duyệt và trust có thời hạn, mọi lần dùng đều được audit.
Dùng tốt cho cá nhân (không cần server) và mở rộng được cho team/doanh nghiệp
(server self-hosted).

Nguyên tắc:

1. **Agent-first.** Mọi tính năng trả lời được câu hỏi: agent nào, dùng secret
   nào, ở đâu, ai cho phép, trong bao lâu, đã làm gì.
2. **Local-first.** Không có server vẫn dùng đầy đủ trên Mac và VPS. Server chỉ
   *thêm* đồng bộ, team, CI/CD, MCP Gateway, web console.
3. **Một sản phẩm, một tên.** KeyLease. Bỏ thương hiệu LeaseGate.
4. **Ít thành phần.** Một binary `keylease` (CLI + daemon), một binary
   `keylease-server` (một Docker image), các app (macOS, mobile), một web console.
5. **Chuẩn phổ biến khi có.** Chỉ tự định nghĩa khi không có chuẩn phù hợp
   (xem mục 6). Không cần đầy đủ chuẩn, chỉ cần có chức năng và tương thích.
6. **Đơn giản trước, chặt sau.** Mặc định dễ dùng (xem ghi chú UX); tuỳ chọn
   chặt hơn cho doanh nghiệp.

---

## 1. Trả lời các câu hỏi đặt tên và tách

### 1.1 Có tách `keylease-cloud` không?

**Tách trong code, gộp khi triển khai.**

- Hiện `keylease-cloud` chứa hai thứ không liên quan: *relay cá nhân*
  (`/v1/relay/*`) và *control plane tổ chức* (organizations, OIDC/SCIM, policy
  releases, edges, SIEM…). Đó là lý do khó hiểu.
- Đề xuất: một binary **`keylease-server`**, bên trong là các module có ranh giới
  rõ (crate riêng): identity, sync, secrets, kms, agent-trust, gateway, console API.
  Người self-host chỉ chạy một image; module bật/tắt bằng cấu hình.
- Không tách thành nhiều binary vì self-host nhiều service là gánh nặng cho cá
  nhân và team nhỏ, và các module dùng chung user, project, audit.

### 1.2 LeaseGate có đổi thành `keylease-control` không?

**Đề xuất bỏ hẳn tên LeaseGate, và dùng `keylease-server` thay vì `keylease-control`.**

- "Server" là cách gọi phổ biến cho bản self-host (server + web console), người
  dùng hiểu ngay. "Control"/"control plane" là thuật ngữ hạ tầng, khó hiểu với
  cá nhân.
- Web UI gọi là **KeyLease Console**.
- Crate `leasegate-*` → `keylease-*` (xem mục 7). Các crate cũ đã lên crates.io:
  phát hành tên mới, đánh dấu tên cũ deprecated.

### 1.3 "Gateway" đổi thành gì?

| Hiện tại | Tên mới | Lý do |
|---|---|---|
| `keylease mcp` (stdio) | **local MCP server** | Thuật ngữ chuẩn của MCP |
| `serve --gateway-url` | **remote MCP server** (`serve --public-url … --remote-mcp`) | Thuật ngữ chuẩn; client gọi là "custom connector" |
| `keylease gateway connect-code/connections/revoke` | `keylease mcp connect-code/connections/revoke` | Cùng nhóm lệnh MCP |
| LeaseGate Edge ("local Gateway") | **managed node** (`keylease serve` liên kết với server) | Edge chỉ là vault node được server quản lý |
| (ý tưởng ProxyHub) | **MCP Gateway** (module `gateway` của server) | Tên phổ biến trong ngành cho proxy gom nhiều MCP server/API và phân phối lại; chữ "gateway" chỉ dùng cho nghĩa này |

Giữ cờ và lệnh cũ làm alias ẩn, có cảnh báo deprecated trong 1–2 bản. Không đổi
giá trị đã nằm trong wire contract (`test-vectors/rpc`).

---

## 2. Mô hình khái niệm

### 2.1 Thực thể

```
User ─┬─ Devices (Mac, mobile, VPS node)        — mỗi device có khoá riêng
      └─ Workspaces
           ├─ Personal workspace (mỗi user một cái)
           └─ Organization workspace (team/doanh nghiệp)
                └─ Projects
                     └─ Environments (dev, staging, production, …)
                          └─ Folders
                               └─ Items (login, ssh_key, database, api_key,
                                         secret (KEY=VALUE), note, …)

Identities dùng secret:
  - Agent identity     (Ed25519, theo project; đã có, ADR 0005)
  - Machine identity   (CI/CD, workload; OIDC federation; mới)
  - Remote MCP client  (OAuth 2.1; đã có)
```

- **Personal vs Project:** Personal workspace có một khu **Personal** kiểu
  password manager (login, thẻ, ghi chú). Agent mặc định *không thấy* khu này.
  Ngoài ra là các project cá nhân (ví dụ `shop`, `blog`), nơi agent làm việc.
  Phân biệt bằng project, không phải bằng vault riêng.
- **Environment** thay cho trường `environment` rời rạc trên item hiện nay. Risk
  tier (R3 cho production) tính theo environment.
- **Folder** = `VaultGroup` hiện có.
- **Item `secret`** (KEY=VALUE) là kiểu mới cho CI/CD và `.env`. Các item phong
  phú (login, ssh, database) giữ nguyên.
- **Tham chiếu:** `kl://<workspace>/<project>/<env>/<path>/<item>#<field>`, mở
  rộng từ `kl://vault/item/field` hiện có.

### 2.2 Hai chế độ lưu trữ project: quyết định kiến trúc quan trọng nhất

| | **Private** (E2EE) | **Managed** (mã hoá phía server bằng KMS) |
|---|---|---|
| Ai giải mã được | Chỉ các device/node là thành viên | Server (qua KMS) và các device thành viên |
| Server thấy gì | Ciphertext, metadata tối thiểu | Plaintext khi cần dùng |
| Dùng cho | Cá nhân, VPS của mình, team nhỏ cần zero-knowledge | CI/CD, MCP Gateway, broker phía server, sửa trên web console, team lớn |
| Ai thực thi policy | Daemon trên device giữ plaintext | Server (cho các lần dùng phía server) + daemon (khi dùng trên node) |
| Không có server | Hoạt động bình thường | Không áp dụng |

Lý do phải có hai chế độ:
- CI/CD (workload chỉ có OIDC token, không giữ khoá) và MCP Gateway (server gọi API
  thay agent) **bắt buộc** server phải giải mã được.
- Đồng bộ cá nhân thì nên zero-knowledge.

Chọn theo project, mặc định: Personal workspace → Private; Organization → Managed
(đổi được). Chuyển Private → Managed cần chủ project xác nhận.

### 2.3 Khoá và device

- Mỗi project có một **project key**. Private: project key được wrap tới public
  key của từng device thành viên. Managed: project key được wrap bởi KMS key
  của server.
- **"Trust một device/VPS" = thêm device đó làm thành viên project** (wrap project
  key tới nó). Đây là khái quát hoá của "share item tới node" (ADR 0006).
- Policy, approval, trust của agent (ADR 0005) giữ nguyên: là thành viên chỉ
  quyết định *dữ liệu có mặt*, còn *agent dùng gì* vẫn do policy quyết định
  (hai cấp định danh như ADR 0006).

### 2.4 Mất khoá trên Mac thì sao? (khôi phục)

Với E2EE, nếu **mọi** đường mở khoá đều mất thì dữ liệu Private không giải mã
được nữa. Đó là bản chất của zero-knowledge. Thiết kế phải làm cho việc mất hết
mọi đường gần như không xảy ra.

**Hiện tại:** vault trên Mac được mã hoá bằng root key, root key được wrap bởi
master password (Argon2id). Có `vault backup` (file backup có xác thực) và, khi
liên kết Cloud, recovery kit (mã 28 ký tự) mở được owner key để khôi phục backup.

**v2: một account key, nhiều "slot" mở khoá độc lập:**

```
                 ┌─ slot master password (Argon2id)       — trên mọi device, và bản mã hoá trên server
account key ─────┼─ slot device (Keychain / Secure Enclave, Touch ID) — mở hằng ngày, không cần gõ password
 (owner)         ├─ slot recovery code (recovery kit, cất offline)
   │             └─ (tuỳ chọn) slot admin tổ chức — chỉ cho workspace Organization
   ▼
project keys (Private) ──► items
```

| Tình huống | Không server | Có server |
|---|---|---|
| Mất hoặc hỏng Mac, còn thiết bị owner khác (iPhone, Mac thứ 2) | Thiết bị kia thêm Mac mới bằng QR | Như trái, hoặc đăng nhập bằng master password |
| Mất hết thiết bị, nhớ master password | Khôi phục từ file backup + master password | Đăng nhập trên máy mới, tải ciphertext, mở bằng master password |
| Quên master password, còn thiết bị đang mở được bằng Touch ID | Đặt master password mới từ thiết bị đó | Như trái |
| Quên master password và mất hết thiết bị | Recovery code + file backup | Recovery code |
| Mất tất cả (password, thiết bị, recovery code, backup) | **Mất dữ liệu Private** | **Mất dữ liệu Private**; project Managed vẫn còn |
| Project Managed | — | Không mất: server cấp lại cho thiết bị mới sau khi đăng nhập + MFA |

Quy tắc UX để tránh mất dữ liệu:
- Lúc tạo vault bắt buộc lưu recovery kit (in, lưu vào trình quản lý mật khẩu
  khác, hoặc chụp), có bước xác nhận.
- Backup tự động (chỉ ciphertext) vào thư mục người dùng chọn, ví dụ iCloud
  Drive, Dropbox, USB, khi không dùng server.
- Cảnh báo rõ khi dữ liệu Private chỉ nằm trên một thiết bị và chưa có recovery kit.
- VPS (node không phải owner) không thêm được thiết bị owner mới; chỉ thiết bị
  owner làm được việc này.
- Key trong Secure Enclave không xuất được, nên luôn cần ít nhất một slot khác.

---

## 3. Kiến trúc thành phần

```
┌──────────── Device / node (Mac, VPS) ────────────┐        ┌────────── keylease-server (self-hosted) ──────────┐
│ keylease (CLI + daemon)                          │        │ identity   users, devices, SSO, SCIM              │
│  ├ vault (SQLite, mã hoá)                        │        │ sync       E2EE sync cho project Private          │
│  ├ policy · approval · trust · audit             │◄──────►│ secrets    project Managed, version, PIT restore   │
│  ├ brokers: ssh-agent, db proxy, http proxy, run │  HTTPS │ kms        root key, project key, API KMS          │
│  ├ local MCP server (stdio)                      │        │ trust      policy, approval, trust tập trung       │
│  └ remote endpoint (tuỳ chọn):                   │        │ machine    machine identity, OIDC federation       │
│      remote MCP server + approver API            │        │ gateway    MCP Gateway, http proxy, dynamic creds │
└──────────────────────────────────────────────────┘        │            phía server                            │
          ▲ Unix socket                                      │ audit      tập trung, export SIEM                 │
   agent CLI (Claude Code, Codex…)                           │ notify     push APNs/FCM/ntfy/Web Push            │
                                                             │ console    web console (cùng binary)              │
 macOS app ── quản lý, approver (Touch ID)                   └───────────────────────────────────────────────────┘
 Mobile app ── approver, xem vault, quét QR                    ▲                ▲               ▲
                                                               CI/CD (OIDC)   ChatGPT/claude.ai  thành viên team
                                                                              (qua MCP Gateway)  (console, CLI)
```

- **Node không có server:** như hiện nay. Approver là macOS app, CLI admin hoặc
  remote approver đã pair.
- **Node liên kết server:** đồng bộ project, nhận policy đã ký (thay thế Edge),
  approval được đẩy tới điện thoại hoặc console.
- **Server không thay thế node:** agent CLI vẫn nói chuyện với daemon local qua
  Unix socket. Server chỉ là nơi đồng bộ, điều phối và chạy broker phía server.

---

## 4. Các luồng sử dụng

### 4.1 Cá nhân, chỉ máy local (không server)
1. Cài app Mac, tạo vault (Personal + project).
2. `keylease projects init` trong thư mục dự án → agent identity theo project.
3. Agent dùng secret qua broker (ssh, db, http proxy, run); approval hiện trên
   Mac, chọn "once" hoặc trust 1h/1d.

### 4.2 Cá nhân + VPS, không server (copy/paste thủ công)
1. Trên VPS: `keylease node init` → in **node ID** (public key, dạng
   `age1…` để dùng chuẩn age).
2. Trên Mac: chọn project hoặc item → **Export to node** → dán node ID → nhận một
   khối text đã mã hoá (age, ký bằng khoá owner) hoặc một mã QR.
3. Trên VPS: `keylease import` → dán khối text. Item vào project tương ứng, ở chế
   độ chỉ đọc nếu là bản share.
4. Approval trên VPS: admin CLI, hoặc pair Mac/điện thoại làm remote approver (đã có).
5. Chiều ngược lại (VPS sinh secret mới, ví dụ `generate-secret`): export từ VPS
   tới khoá owner, rồi dán vào Mac.

Cùng một định dạng bundle được dùng cho sync qua server, nên sau này nâng cấp
lên server không phải đổi gì.

### 4.3 Cá nhân + server
- Thêm device bằng QR hoặc mã một lần; project Private tự đồng bộ hai chiều giữa
  các device thành viên (thay cho giới hạn "không có live sync" hiện nay).
- VPS là device thành viên của các project được chọn. Không còn copy/paste.
- Recovery kit giữ nguyên ý tưởng (ADR 0006).

### 4.4 Team / doanh nghiệp
- Organization → project → environment. Vai trò: owner, admin, member, viewer,
  cộng quyền theo environment/folder.
- Chia sẻ: thêm member hoặc group vào project; link chia sẻ một lần có hạn.
- Thay đổi secret ở production cần duyệt (change request); xin quyền tạm thời
  (access request) → approval + trust có hạn (dùng lại mô hình ADR 0005).
- Version và khôi phục theo thời điểm (point-in-time) cho project Managed.

### 4.5 CI/CD
- **Machine identity** với OIDC federation: GitHub Actions, GitLab CI, Kubernetes
  service account; không cần secret dài hạn.
- Cách lấy secret: `keylease run --project shop --env production -- cmd`,
  GitHub Action `keylease/secrets-action`, xuất `.env`, provider cho
  External Secrets Operator trên Kubernetes.
- Policy và audit giống agent: machine identity cũng là một identity.

### 4.6 MCP Gateway (ý tưởng ProxyHub)
- Admin kết nối upstream một lần trên console: remote MCP server (Linear,
  GitHub MCP… qua OAuth hoặc token), REST API (qua HTTP broker), connector có
  sẵn (`keylease-connectors`).
- Gateway phân phối: mỗi team, người hoặc agent nhận **một endpoint remote MCP** với
  danh sách tool được phép; credential nằm ở server.
- Mỗi tool call qua policy → approval/trust → audit. Kết quả bị giới hạn bởi
  `DataBudget`.
- Agent local cũng dùng được (`claude mcp add --transport http …`).

### 4.7 HTTP credential proxy
Theo plan riêng (bộ nhớ: `http-proxy-plan`): proxy local trên node cho project
Private; phía server cho project Managed (cùng lõi forwarder, đặt trong module gateway).

---

## 5. Agent trust layer: cái giữ nguyên và cái mở rộng

| Thành phần | Hiện có | Mở rộng v2 |
|---|---|---|
| Định danh | Agent Ed25519 ký request, trust theo project | Thêm machine identity (OIDC), remote MCP client trong MCP Gateway; device identity cho thành viên project |
| Policy | Deterministic, deny-by-default, risk tier | Policy viết tập trung trên server, ký và đẩy xuống node (dùng lại policy bundle) |
| Approval | Theo digest, trust có thời hạn, remote approver, ntfy | Duyệt trên mobile/console (ký bằng passkey/WebAuthn), change request, access request |
| Tiers T0–T4 | T0 connector/db query, T1 ssh/db, T3 run, T4 reveal | T1 HTTP proxy, T0 `http_request`, MCP Gateway, T2 dynamic creds nối vào node |
| Audit | Hash-chain trên node | Gom về server, export SIEM, xem trên console |

---

## 6. Chuẩn áp dụng theo loại chức năng

| Loại | Chuẩn | Ưu tiên |
|---|---|---|
| Đăng nhập SSO | OpenID Connect | P3 |
| Đồng bộ người dùng | SCIM 2.0 | P6 (đã có code cũ) |
| Ký approval, MFA | WebAuthn / passkeys | P2–P3 |
| Auth cho MCP | OAuth 2.1 + RFC 9728, 8414, 7591 (đã có) | — |
| CI/CD | OIDC workload identity federation (JWT/JWKS); Kubernetes TokenReview | P4 |
| Truyền secret thủ công | **age** (X25519 recipients) + chữ ký Ed25519; QR | P1 |
| Import/export | `.env`, 1PUX, KDBX (đã có), CSV | P1 |
| Kubernetes | External Secrets Operator (provider webhook trước) | P4 |
| KMS: thao tác | REST: encrypt/decrypt, sign/verify, MAC; key version, rotation | P3 (nội bộ), P6 (API) |
| KMS: root key | Khoá từ env/file, AWS KMS, GCP KMS, Azure Key Vault, HSM qua PKCS#11 | P3 (env + 1 cloud KMS), P6 (PKCS#11) |
| KMS: giao thức thiết bị | KMIP | Chỉ khi có nhu cầu doanh nghiệp |
| SSH | OpenSSH agent protocol, OpenSSH certificates (đã có) | — |
| Database | PostgreSQL wire + SCRAM (đã có); MySQL | P5 |
| HTTP broker | HTTP proxy (CONNECT, `HTTPS_PROXY`), base-URL | P1–P2 |
| MCP | stdio, Streamable HTTP | — |
| Dynamic creds | AWS STS, SSH CA, PostgreSQL role (đã có ở `leasegate-credentials`) | P5 |
| Audit export | JSON Lines, syslog RFC 5424, OpenTelemetry logs, webhook | P6 |
| Push | APNs, FCM, ntfy (đã có), Web Push | P2 |

Tự định nghĩa (không có chuẩn phù hợp): mô hình policy và approval, trust có
thời hạn, wire protocol giữa node và server.

---

## 7. Kế hoạch refactor code

### 7.1 Ánh xạ crate

| Hiện tại | v2 | Ghi chú |
|---|---|---|
| `keylease-core`, `-crypto`, `-store` | giữ | Thêm workspace, environment, project key, item `secret` |
| `keylease-service` (16,5k dòng) | giữ tên, **tách module**: `vault`, `trust` (policy/approval/trust), `broker` (ssh, db, http, inject), `identity` | Có thể tách crate `keylease-broker` |
| `keylease-cli` (10,3k dòng) | giữ binary `keylease`; HTTP của node (remote MCP, approver) chuyển sang crate `keylease-node-http` | |
| `keylease-rpc`, `keylease-mobile` | giữ | |
| `leasegate-policy` | `keylease-policy` | |
| `leasegate-control` + `leasegate-policy-bundle` | `keylease-protocol` | Wire protocol giữa node và server |
| `leasegate-mcp` + MCP trong CLI (`mcp.rs`, `gateway.rs`) | `keylease-mcp` | Một bản cài đặt MCP dùng cho local, remote và MCP Gateway |
| `leasegate-connectors`, `-connector-sdk` | `keylease-connectors`, `-connector-sdk` | Nguồn cho MCP Gateway |
| `leasegate-credentials` | `keylease-credentials` | Dynamic creds |
| `keylease-cloud` | `keylease-server` (bin) + `keylease-server-{identity,sync,secrets,kms,gateway,console}` | Relay chuyển thành module sync; phần tổ chức chuyển thành identity/secrets |
| `leasegate-edge` | **bỏ**, gộp vào `keylease serve` chế độ managed | Dùng lại code cache policy đã ký |
| `keylease-sync` (175 dòng mô phỏng) | thay bằng sync engine thật hoặc bỏ | |

### 7.2 Ứng dụng

| Hiện tại | v2 |
|---|---|
| `apps/desktop-macos(-app)` | giữ: quản lý + approver |
| `apps/mobile-flutter` + `packages/leasegate_vault_ui` | app mobile (làm sau P2, chắc chắn có): vault, approver, quét QR; công nghệ chốt khi bắt đầu |
| `apps/mobile-android` (Kotlin/Compose) | cần quyết định: bỏ nếu Flutter là hướng chính |
| `apps/approval-flutter` (web/mobile cho operator) | gộp: phần duyệt vào app mobile, phần quản trị vào web console |
| (mới) Web console | SPA, phục vụ bởi `keylease-server` (nhúng vào binary); stack ở mục 11 |

### 7.3 Code doanh nghiệp đang có

OIDC, SCIM, access review, compliance evidence, SIEM, policy release, operator
device trong `keylease-cloud`: **đóng băng**, không phát triển thêm cho tới P3/P6,
rồi chuyển vào các module mới. Không xoá để giữ công sức đã làm.

---

## 8. Lộ trình

Thứ tự ưu tiên cá nhân trước, vì đó là nơi sản phẩm dùng được ngay.

| Phase | Nội dung | Kết quả |
|---|---|---|
| **P0: Dọn tên và cấu trúc** | Đổi gateway → remote MCP; `leasegate-*` → `keylease-*`; tách module `keylease-service`; viết lại docs theo mô hình mới; quyết định app Android | Không đổi hành vi; dễ hiểu |
| **P1: Cá nhân hoàn chỉnh, không server** | Workspace/Personal/Project/Environment; item `secret`; export/import age + QR giữa Mac và VPS; HTTP proxy (base-URL) | Dùng trọn vẹn cho cá nhân + VPS |
| **P2: Nền server** | `keylease-server`: identity (user, device), E2EE sync project Private, push, console v1 (device, approval, audit) | Đồng bộ nhiều device |
| **P3: Team + Managed** | Organization, RBAC, chia sẻ, project Managed + KMS (root key env/cloud KMS), version/PIT, change request, SSO OIDC | Dùng cho team |
| **P4: CI/CD** | Machine identity, OIDC federation, GitHub Action, provider ESO, `keylease run` lấy từ server | Pipeline không giữ secret dài hạn |
| **P5: MCP Gateway + broker phía server** | Upstream MCP/OAuth, allowlist tool, phân phối endpoint, HTTP proxy phía server, dynamic creds, MySQL | "ProxyHub" |
| **P6: Doanh nghiệp** | KMS API công khai, PKCS#11/HSM, SCIM, export SIEM, managed node (thay Edge) | Đáp ứng yêu cầu doanh nghiệp |

### 8.1 Thứ tự triển khai (mỗi bước là một PR)

Nguyên tắc: mỗi PR build được, test qua và không làm hỏng người dùng hiện có
(cờ/lệnh cũ giữ làm alias). PR xếp chồng theo thứ tự; PR sau base trên PR trước
cho tới khi PR trước được merge.

| # | Phase | PR | Nội dung chính |
|---|---|---|---|
| 1 | P0 | `docs/platform-v2` | Plan này + khung web console `apps/console` + job CI |
| 2 | P0 | `refactor/drop-leasegate` | `leasegate-*` → `keylease-*` (policy, protocol = control + policy-bundle, mcp, connectors, connector-sdk, credentials); bỏ chữ LeaseGate trong code/docs; Edge đổi tên tạm `keylease-edge` (bỏ hẳn ở P6) |
| 3 | P0 | `refactor/remote-mcp-names` | `serve --public-url … --remote-mcp`, `keylease mcp connect-code/connections/revoke`; cờ/lệnh `gateway` cũ thành alias ẩn có cảnh báo |
| 4 | P0 | `refactor/server-and-modules` | Binary `keylease-server` (giữ `keylease-cloud` làm alias); tách `keylease-service` thành module `vault`, `trust`, `broker`, `identity` |
| 5 | P1 | `feat/environments-and-secrets` | Environment là thực thể; item `secret` (KEY=VALUE); khu Personal ẩn với agent; `kl://` mở rộng; migration vault v1 tự động |
| 6 | P1 | `feat/age-bundles` | `keylease node init`, export/import bundle age có chữ ký, QR; import `.env`/CSV |
| 7 | P1 | `feat/http-proxy` | ADR 0007; forwarder trong service + chế độ base-URL; MCP `http_request` |
| 8 | P1 | `feat/http-proxy-mitm` | Chế độ `HTTPS_PROXY` với CA tạm theo lần chạy |
| 9 | P2 | `feat/server-identity` | ADR 0008; module identity (user, device, phiên đăng nhập, WebAuthn) |
| 10 | P2 | `feat/server-sync` | Sync E2EE project Private (last-writer-wins theo item + lịch sử version); node liên kết server |
| 11 | P2 | `feat/console-v1` | API console + nhúng `dist/` vào binary; trang thiết bị, approval, audit; push Web Push/ntfy |
| 12 | P3 | `feat/orgs-rbac` | Organization, vai trò, chia sẻ project |
| 13 | P3 | `feat/managed-projects-kms` | Project Managed, KMS (root key env/file + AWS KMS), version/PIT restore |
| 14 | P3 | `feat/change-requests-sso` | Change request, access request, SSO OIDC (chuyển code OIDC cũ) |
| 15 | P4 | `feat/machine-identity` | Machine identity, OIDC federation (GitHub, GitLab, Kubernetes), `keylease run` lấy từ server |
| 16 | P4 | `feat/ci-integrations` | GitHub Action, webhook provider cho External Secrets Operator |
| 17 | P5 | `feat/mcp-gateway` | Upstream MCP/OAuth, allowlist tool, endpoint theo team/agent |
| 18 | P5 | `feat/server-brokers` | HTTP proxy phía server, dynamic creds, MySQL |
| 19 | P6 | `feat/enterprise` | KMS API công khai, PKCS#11, SCIM, export SIEM, managed node (bỏ Edge) |

App mobile: sau bước 11, khi chốt công nghệ (mục 12). Quyết định mở 3–5 ở mục 9
lấy theo đề xuất (last-writer-wins, migration tự động, console chỉ hiện metadata
của project Private) trừ khi có thay đổi.

---

## 9. Quyết định

Đã chốt (2026-11-14):

- **Bỏ tên LeaseGate.** Dùng `keylease-server` + KeyLease Console.
- **MCP Gateway** là tên của module ProxyHub (tên phổ biến trong ngành).
- **App mobile làm sau, nhưng chắc chắn có.** Không nằm trong P0–P2; công nghệ
  quyết định khi bắt đầu.
- **Hai chế độ Private/Managed** (mục 2.2), kèm thiết kế khôi phục khoá (mục 2.4).
- **Web console là SPA dùng React + TypeScript + Vite + TanStack Router** (mục 11).
  Không dùng TanStack Start vì console không cần server JS.

Còn mở:

1. **App mobile** (mục 12): native + Rust core (khuyến nghị) hay Flutter?
2. **App Android Kotlin `mobile-android`** và `mobile-flutter`: giữ cái nào khi làm mobile?
3. **Sync Private khi nhiều device cùng sửa**: last-writer-wins theo item có
   lịch sử version (đơn giản, khuyến nghị) hay merge theo field?
4. **Tương thích ngược**: vault v1 nâng cấp tại chỗ (migration) hay xuất/nhập lại?
   Đề xuất: migration tự động; vault cũ thành Personal workspace, các
   `VaultProject` thành project.
5. **Web console có xem/sửa project Private không?** Cần mã hoá phía trình duyệt
   (WASM). Đề xuất: v1 chỉ hiện metadata, để sau.

## 10. Rủi ro

- **Phạm vi lớn.** Phải giữ P0–P1 nhỏ và phát hành được; server chỉ bắt đầu khi
  cá nhân đã ổn.
- **Managed mode** nghĩa là ai vận hành server (bạn hoặc admin công ty) giải mã
  được. Phải nói rõ trong docs và UI.
- **Sync E2EE nhiều device:** thu hồi device không xoá được thứ nó đã thấy, nên
  cần rotate. Đã ghi nhận trong ADR 0006, giữ nguyên nguyên tắc.
- **Đổi tên crate trên crates.io** ảnh hưởng người dùng hiện có: cần bản phát
  hành chuyển tiếp.
- **Same-UID** vẫn là non-goal của node (ADR 0005).

---

## 11. Web console: so sánh tech stack (SPA)

### Yêu cầu riêng của KeyLease Console

- **Bảo mật trước tiên:** CSP chặt (không inline script), ít dependency (giảm
  rủi ro chuỗi cung ứng npm), không SSR (không có Node chạy phía server).
- **Nhúng vào `keylease-server`:** build ra file tĩnh, axum phục vụ (nhúng bằng
  `rust-embed`/`include_dir`), một image duy nhất.
- **Kiểu dữ liệu sinh từ Rust:** đã có `schemars`, thêm OpenAPI (ví dụ `utoipa`)
  rồi sinh client TypeScript, để API không lệch giữa server và UI.
- **Sau này có crypto phía trình duyệt** (xem project Private): biên dịch
  `keylease-crypto` sang WASM. Framework nào cũng gọi được WASM.
- **WebAuthn/passkeys** để ký approval; i18n (Việt, Anh); giao diện quản trị
  nhiều bảng, form, lọc audit.
- **Agent viết code tốt:** framework phổ biến thì AI coding agent viết đúng hơn.

### Các lựa chọn

| Stack | Ưu điểm | Nhược điểm | Hợp với KeyLease |
|---|---|---|---|
| **React + TypeScript + Vite** (TanStack Router/Query, shadcn/ui + Radix + Tailwind) | Hệ sinh thái lớn nhất; nhiều thư viện admin, bảng, form; AI agent viết tốt nhất; dễ tuyển người; shadcn/ui là code copy vào repo (ít dependency runtime) | Nhiều lựa chọn phải tự ghép; bundle lớn hơn Svelte/Solid; dependency npm nhiều nếu không kỷ luật | **Cao: khuyến nghị** |
| **Vue 3 + TypeScript + Vite** (Vue Router, Pinia, PrimeVue hoặc Naive UI) | Dễ học, template rõ ràng; thư viện component admin đầy đủ; tài liệu tốt | Hệ sinh thái và lượng ví dụ ít hơn React; TypeScript trong template kém chặt hơn TSX | Khá |
| **SvelteKit (chế độ static/SPA)** + TypeScript | Bundle nhỏ, nhanh; code ngắn; trải nghiệm dev tốt | Hệ sinh thái component admin nhỏ hơn; Svelte 5 (runes) còn mới nên AI agent hay viết theo cú pháp cũ; ít người biết hơn | Khá |
| **SolidJS + Vite** | Hiệu năng rất tốt, cú pháp gần React | Cộng đồng nhỏ; ít thư viện admin; rủi ro thiếu người bảo trì | Thấp |
| **Angular** | Đầy đủ sẵn (router, form, DI, i18n); có cấu trúc cho team lớn | Nặng, nhiều khái niệm; quá tầm cho console nhỏ; tốc độ phát triển chậm hơn | Thấp |
| **Rust WASM: Leptos / Dioxus / Yew** | Một ngôn ngữ cho cả server và UI; dùng chung type và crate crypto trực tiếp | Hệ sinh thái UI non trẻ, ít component; build chậm, bundle WASM lớn; ít người đóng góp; API framework còn thay đổi | Thấp (chỉ hấp dẫn về mặt "toàn Rust") |
| **Flutter web** (dùng lại `approval-flutter`) | Dùng lại code Dart, chung với mobile | Render canvas: không giống web thật, SEO/accessibility/copy-paste kém; bundle rất lớn; đã chọn SPA web | Loại |
| **HTMX + template phía server (askama)** | Gần như không có JS, cực ít dependency, bảo mật dễ | Không phải SPA; tương tác phức tạp (WebAuthn, crypto WASM, bảng lớn) khó; trái với quyết định SPA | Loại (nhưng hợp cho trang consent OAuth hiện có) |
| **Next.js / Nuxt (SSR)** | Phổ biến, nhiều tính năng | Cần runtime Node phía server, trái với "một binary Rust"; SSR không cần cho console | Loại |

### Đề xuất

**React + TypeScript + Vite + TanStack Router** (đã chốt 2026-11-14), cụ thể:

- Routing và dữ liệu: **TanStack Router** (route có type, file-based routing qua
  plugin Vite, tách code theo route) + **TanStack Query** (cache API). Không dùng
  TanStack Start: giá trị chính của nó là SSR và server function chạy trên JS,
  trong khi backend của console là `keylease-server` (Rust). Router dùng chung
  định nghĩa route với Start, nên sau này có cần thì chuyển sang vẫn dễ.
- UI: **shadcn/ui** (Radix + Tailwind): component copy vào repo, dễ kiểm soát và
  dễ audit; icon **lucide-react**; **TanStack Table** cho bảng audit và danh sách secret.
- Form và kiểm tra dữ liệu: **React Hook Form** + **Zod** (Zod cũng dùng cho
  `validateSearch` của router).
- API client: sinh từ OpenAPI của server (**openapi-typescript** + `openapi-fetch`);
  phía Rust sinh OpenAPI bằng **utoipa**.
- WebAuthn: **@simplewebauthn/browser**. i18n: **i18next** + `react-i18next`.
- Test: **Vitest** + **Playwright**. Lint: **ESLint** + `typescript-eslint` +
  `eslint-plugin-react-hooks`.
- Gói: **pnpm** với lockfile, chặn script cài đặt (`ignore-scripts`), kiểm tra
  dependency trong CI.
- Triển khai: `pnpm build` → thư mục tĩnh → nhúng vào `keylease-server`, CSP
  `script-src 'self'`.

#### Phiên bản (bản stable mới nhất, kiểm tra trên npm/crates.io ngày 2026-11-14)

| Thành phần | Phiên bản | Ghi chú |
|---|---|---|
| Node.js | 26 LTS (26.13.x) | Chỉ dùng để build; ghi trong `.nvmrc` và `engines`. Không dùng Bun: console là SPA tĩnh, không có JS phía server, lợi ích về tốc độ không đáng so với rủi ro tương thích công cụ |
| pnpm | 12.18 | Khoá bằng trường `packageManager`; CI dùng `pnpm/action-setup` (Node 25+ không còn kèm Corepack) |
| TypeScript | **6.0.3** | Không dùng 7.0 lúc này: `typescript-eslint` 8.72 chỉ hỗ trợ TS < 6.1. Lên 7.x khi `typescript-eslint` hỗ trợ |
| react, react-dom | 19.3.1 | `@types/react` 19.3 |
| vite | 8.3.8 | |
| @vitejs/plugin-react | 6.3.0 | Yêu cầu Vite 8 |
| @tanstack/react-router | 1.170.x | + `@tanstack/router-plugin` 1.169, `@tanstack/react-router-devtools` 1.167 (chỉ bản dev) |
| @tanstack/react-query | 5.107.x | + `@tanstack/react-query-devtools` (chỉ bản dev) |
| @tanstack/react-table | 9.3.x | API v9 khác v8; ví dụ cũ trên mạng phần lớn là v8 |
| tailwindcss, @tailwindcss/vite | 4.3.5 | Cấu hình bằng CSS (`@theme`), không cần `tailwind.config.js` |
| shadcn (CLI), radix-ui | 4.23 / 1.8.1 | Dùng gói gộp `radix-ui` thay vì từng gói `@radix-ui/*` |
| lucide-react | 1.73 | |
| react-hook-form, @hookform/resolvers | 7.92 / 7.0.6 | |
| zod | 4.6.x | Zod 4 (cú pháp khác Zod 3 ở một số chỗ) |
| openapi-typescript, openapi-fetch | 7.13 / 0.17 | |
| @simplewebauthn/browser | 14.0 | |
| i18next, react-i18next | 27.1 / 18.0 | |
| vitest | 5.1 | |
| @playwright/test | 1.65 | |
| eslint, typescript-eslint, eslint-plugin-react-hooks | 10.15 / 8.72 / 7.1 | ESLint flat config |
| utoipa (Rust) | 6.0 | Sinh OpenAPI từ `keylease-server` |

Quy tắc phiên bản: ghi chính xác phiên bản trong `package.json` (không dùng `^`),
cập nhật qua Renovate/Dependabot theo nhóm, chỉ nhận bản đã phát hành ít nhất
7 ngày (`minimumReleaseAge` của pnpm). Ghi các mốc major (Zod 4, TanStack Table 9,
Tailwind 4, Vite 8) vào `AGENTS.md` của console để agent không viết theo API cũ.

#### Trạng thái triển khai

Khung console đã tạo tại `apps/console` (2026-11-14): layout, route Tổng quan /
Thiết bị / Phê duyệt / Audit, i18n Việt–Anh, client OpenAPI có type (hiện chỉ có
`/healthz`, file `openapi.json` viết tay cho tới khi `keylease-server` sinh bằng
utoipa), kiểm tra CSP khi build, Vitest, Playwright và job `console` trong CI.
Các trang Thiết bị, Phê duyệt, Audit chờ API của P2. Việc nhúng `dist/` vào
binary làm cùng `keylease-server`.

Lý do: an toàn và quen thuộc nhất cho một console quản trị nhiều bảng và form;
AI agent và cộng tác viên viết đúng ngay; mọi yêu cầu (WebAuthn, WASM, OpenAPI)
đều có thư viện trưởng thành. Đã chốt React (2026-11-14); Svelte và Vue được
cân nhắc nhưng không chọn.

---

## 12. App mobile: so sánh công nghệ (làm sau, chưa chốt)

### Yêu cầu riêng

- Dùng lại Rust core (`keylease-core/crypto/store/rpc`), chạy trong process
  (ADR 0004), giữ secret ngoài heap có GC càng nhiều càng tốt.
- Tích hợp nền tảng sâu: Keychain/Keystore, Secure Enclave/StrongBox, Face ID,
  push APNs/FCM có nút **Duyệt/Từ chối ngay trên thông báo**, camera quét QR,
  sau này **AutoFill / passkey provider**. Đây là *extension* hệ điều hành, phải
  viết native, giới hạn bộ nhớ chặt.
- Vai trò chính: approver, xem vault, thêm thiết bị. Không cần UI phức tạp.

### Các lựa chọn

| Công nghệ | Ưu | Nhược | Đánh giá |
|---|---|---|---|
| **Native: SwiftUI (iOS) + Kotlin/Compose (Android) + Rust core** | Tích hợp nền tảng tốt nhất (extension, thông báo có action, Secure Enclave); kiểm soát bộ nhớ secret tốt nhất; **iOS dùng chung code SwiftUI và `KeyLeaseCore` với app macOS**; đã có khung `apps/mobile-android` (Compose) | Hai UI, hai ngôn ngữ; tốn công gấp đôi phần giao diện | **Khuyến nghị** |
| **Flutter + Rust core** (đã có `mobile-flutter`, `vault_ui`, `keylease-mobile`) | Một UI cho hai nền tảng; trưởng thành; đã có code và ADR 0004 | Extension (AutoFill), notification action vẫn phải viết native; không dùng chung với app macOS SwiftUI; thêm ngôn ngữ Dart | Khá (phương án một codebase) |
| **React Native + Rust (JSI / uniffi)** | Cùng React/TypeScript với web console; New Architecture đã ổn | Secret đi qua heap JS; nối Rust phức tạp hơn; extension vẫn native | Khá |
| **Kotlin / Compose Multiplatform** | Một UI Kotlin cho cả hai; tốt cho đội Android | Logic dùng chung của KMP trùng vai trò với Rust core sẵn có; giao diện iOS không hoàn toàn native | Thấp–Khá |
| **Tauri 2 mobile** | Rust + webview; có thể dùng lại UI React của web console | Mobile còn non; API nền tảng phải viết plugin Swift/Kotlin; webview không hợp extension | Thấp |
| **Dioxus** (Rust, cross-platform) | Toàn bộ là Rust, gọi thẳng crate core, không cần FFI; một codebase cho desktop/web/mobile | Mobile mặc định chạy **webview**; renderer native (Blitz) còn **thử nghiệm**; docs ghi Android "khá thử nghiệm, cần nhiều cấu hình"; API nền tảng (Keychain, push action, extension) phải tự viết JNI/Objective-C; hệ sinh thái nhỏ | **Chưa phù hợp** cho app bảo mật lúc này; xem lại khi native renderer ổn định |

### Đề xuất

**Native + Rust core dùng chung:**
- iOS: SwiftUI, dùng chung package `KeyLeaseCore` và phần lớn view với app macOS.
- Android: Kotlin + Compose (tiếp tục `apps/mobile-android`).
- Rust core qua C ABI hiện có (`keylease-mobile`), dữ liệu bí mật truyền dạng
  byte, không qua `String` của JVM (đúng lo ngại trong ADR 0004).
- Flutter là phương án dự phòng nếu muốn một codebase; khi đó phần extension
  vẫn viết native.
