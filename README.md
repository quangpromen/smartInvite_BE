# SmartInvite Backend

Backend API cho nền tảng thiệp cưới và thiệp sự kiện số SmartInvite, xây dựng trên **ASP.NET Core (.NET 10)**, **Entity Framework Core 10** và **Microsoft SQL Server**.

## 1. Phạm vi hiện tại (Phase BE1 — Simplified Identity + JWT Bearer & Refresh Cookie)

- **Trạng thái hiện tại:** Phase **BE1 — SQL Server Simplified Identity, JWT Bearer Authentication & Authorization Foundation** (`PARTIAL` khi chưa cung cấp kết nối SQL Server test database thực tế; sẵn sàng áp dụng migration và chạy toàn bộ SQL Server integration tests ngay khi cấp biến môi trường test database `*_Test`).
- **Mô hình người dùng tối giản trên ASP.NET Core Identity:**
  - Đăng nhập bằng **Email** và **Password** trên nền **ASP.NET Core Identity** (`ApplicationUser : IdentityUser<Guid>`, `IdentityRole<Guid>`).
  - `ApplicationUser` chỉ bổ sung **3 trường tùy chỉnh**: `DisplayName` (bắt buộc, tối đa `150` ký tự), `CreatedAt` (UTC) và `LastLoginAt` (UTC, nullable).
  - **Không sử dụng bảng `HostProfiles`**, không lưu `OrganizationName`, không dùng `AccountStatus` tùy chỉnh, không dùng `RowVersion` hay `UpdatedAt` tùy chỉnh (sử dụng `ConcurrencyStamp` chuẩn của Identity).
  - **Không sử dụng số điện thoại trong nghiệp vụ:** Hai cột chuẩn của Identity (`PhoneNumber`, `PhoneNumberConfirmed`) giữ trong schema `AspNetUsers` nhưng không xuất hiện trong request, response, DTO, validation hay bất kỳ luồng nghiệp vụ nào (`NULL` / `false`).
  - **Xác nhận email (`EmailConfirmed`):** BE1 chưa triển khai luồng gửi/xác minh email nên cấu hình `SignIn.RequireConfirmedEmail = false` và giữ `EmailConfirmed = false`.
  - Hai vai trò hệ thống: `ADMIN` và `HOST`.
- **Cơ chế Xác thực JWT Bearer + Refresh Cookie & Khóa tài khoản:**
  - **Access Token:** JWT Bearer ngắn hạn (`15 phút` mặc định, ký `HS256` qua `Jwt__SigningKey`), trả trong JSON response, gửi qua header `Authorization: Bearer <accessToken>`, chứa claim `sst` (`SHA-256` của `SecurityStamp`) để kiểm tra thu hồi tức thời và trạng thái Identity Lockout trên từng request xác thực.
  - **Refresh Token:** Chuỗi ngẫu nhiên mật mã (`64` random bytes `Base64Url`, thời hạn `7 ngày` mặc định), chỉ gửi qua cookie `HttpOnly` `Secure` `__Host-SmartInvite.Refresh` (`SameSite=Lax`, `Path=/api/auth`, `Domain=null`), chỉ lưu băm `SHA-256` hex trong bảng `RefreshTokens` trên SQL Server, hỗ trợ **rotation**, kiểm soát đồng thời nguyên tử và **reuse detection** thu hồi toàn bộ `FamilyId`.
  - **Lockout & Revocation:** Khóa tạm thời tự động khi nhập sai mật khẩu (`5 lần / 15 phút`) và khóa/mở khóa chủ động bởi `ADMIN` (`POST /api/admin/hosts/{hostId}/lock`, `POST /api/admin/hosts/{hostId}/unlock`) kết hợp xoay `SecurityStamp` (và thu hồi refresh token khi lock) làm JWT cũ mất hiệu lực ngay lập tức và không tự hoạt động lại sau khi unlock.
  - **CSRF theo metadata:** Bắt buộc cookie `__Host-SmartInvite.Antiforgery` + header `X-CSRF-TOKEN` trên các endpoint thao tác qua cookie (`POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout`); các API dùng thuần `Authorization: Bearer` không yêu cầu CSRF.
  - **CORS & Rate Limiting:** Danh sách trắng origin (cấm wildcard `*`, cho phép `Authorization` và `X-CSRF-TOKEN`) cùng giới hạn tốc độ chống brute-force/flood trên `/api/auth/login` (`5 requests / 15 phút`) và `/api/auth/refresh` (`15 requests / 5 phút`).
  - Cơ chế **Admin Bootstrap** an toàn, idempotent qua biến môi trường tiến trình.
- **Chưa triển khai trong BE1 (thuộc BE2–BE7):** `Event`, `CardDesign`, `Guest`, `Invitation`, `RSVP`, `CheckIn`, `Analytics` và tích hợp Frontend.

Chi tiết quyết định kiến trúc xác thực hiện hành xem tại [docs/adr/002-jwt-bearer-and-refresh-cookie-authentication.md](docs/adr/002-jwt-bearer-and-refresh-cookie-authentication.md) (lịch sử giai đoạn cookie xem tại [docs/adr/001-cookie-authentication.md](docs/adr/001-cookie-authentication.md)).

## 2. Cấu trúc dự án & Chiều phụ thuộc

```text
E:\Code\smartinviteBE
├── SmartInvite.sln
├── Directory.Build.props
├── Directory.Packages.props
├── NuGet.Config
├── .config/dotnet-tools.json         # Local dotnet-ef 10.0.0 tool manifest
├── docs/adr/
│   ├── 001-cookie-authentication.md
│   └── 002-jwt-bearer-and-refresh-cookie-authentication.md
├── src/
│   ├── SmartInvite.Domain/           # RoleNames, Error/ErrorCodes/Result
│   ├── SmartInvite.Application/      # Minimal DTOs, JwtOptions/validator, auth contracts, policies (không phụ thuộc AspNetCore/EF)
│   ├── SmartInvite.Infrastructure/   # EF Core SQL Server, Identity, RefreshToken, JwtAccessTokenService, RefreshTokenService, migrations
│   └── SmartInvite.Api/              # Minimal API endpoints, RefreshCookieService, CSRF/CORS/RateLimit/Swagger/Exception middleware
└── tests/
    ├── SmartInvite.UnitTests/        # Domain/Application rules, JwtOptions, JWT claims, RefreshToken hashing/rotation rules, CurrentUser
    ├── SmartInvite.ArchitectureTests/# Dependency & Clean Architecture boundary rules
    └── SmartInvite.IntegrationTests/ # Non-DB HTTP JWT/CSRF/Swagger security tests & SQL Server integration suite
```

Chiều phụ thuộc bắt buộc: `Domain` ← `Application` ← `Infrastructure` ← `Api`. Cả `Domain` và `Application` đều không tham chiếu `Microsoft.AspNetCore.*` hay `Microsoft.EntityFrameworkCore.*`.

## 3. Chiến lược Xác thực, Lockout, CSRF, CORS và Rate Limiting

### 3.1. JWT Bearer Access Token & Refresh Cookie Rotation
- **Access Token (`Authorization: Bearer <accessToken>`):**
  - Mặc định `15 phút` (`Jwt:AccessTokenMinutes = 15`), `Issuer = SmartInvite.Api`, `Audience = SmartInvite.Web`, `ClockSkew = 30s`.
  - Không lưu trong cookie, không lưu trong database, không ghi ra log.
- **Refresh Cookie (`__Host-SmartInvite.Refresh`):**
  - `HttpOnly=true`, `Secure=Always`, `SameSite=Lax`, `Path=/api/auth`, `Domain=null`, thời hạn mặc định `7 ngày` (`Jwt:RefreshTokenDays = 7`).
  - Không trả refresh token trong JSON response; database chỉ lưu băm `SHA-256` hex (`TokenHash`).
  - Mỗi lần gọi `POST /api/auth/refresh` thành công sẽ rotate sang refresh token mới trong cùng `FamilyId`; nếu một token cũ đã rotate/revoke bị gửi lại, toàn bộ `FamilyId` bị thu hồi ngay lập tức.
- **Identity Lockout & Admin Lock/Unlock:**
  - Nhập sai mật khẩu `5` lần liên tiếp sẽ tự động khóa tạm thời trong `15 phút`.
  - `POST /api/admin/hosts/{hostId}/lock`: bật khóa vĩnh viễn (`LockoutEnd = DateTimeOffset.MaxValue`), xoay `SecurityStamp` và thu hồi toàn bộ refresh token đang hoạt động của `HOST`.
  - `POST /api/admin/hosts/{hostId}/unlock`: mở khóa (`LockoutEnd = null`, `AccessFailedCount = 0`) và xoay `SecurityStamp` mà không đặt lại mật khẩu và không tự đăng nhập `HOST`.

### 3.2. Bảo vệ CSRF cho các Endpoint dùng Cookie
Chỉ các endpoint thao tác qua cookie (`POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout`) mới yêu cầu CSRF cookie + header `X-CSRF-TOKEN`:
1. Gọi `GET /api/auth/csrf` qua HTTPS (kèm `credentials: "include"` trên trình duyệt).
2. Server đặt cookie `__Host-SmartInvite.Antiforgery` (`HttpOnly=true`, `Secure=Always`, `SameSite=Lax`, `Path=/`) và trả về JSON:
   ```json
   {
     "data": {
       "requestToken": "<antiforgery-request-token>"
     }
   }
   ```
3. Đính kèm `requestToken` vào header `X-CSRF-TOKEN` khi gọi `/api/auth/login`, `/api/auth/refresh` hoặc `/api/auth/logout`.
4. Các API xác thực bằng `Authorization: Bearer` (`/api/auth/me`, `/api/auth/logout-all`, `/api/admin/hosts/*`) **không** yêu cầu header `X-CSRF-TOKEN`.

### 3.3. Cấu hình CORS
- Đọc từ mảng cấu hình `Cors:AllowedOrigins` (mặc định rỗng `[]` trong `appsettings.json` — không mở CORS mặc định, chặn wildcard `*`).
- Cho phép `AllowCredentials()` cùng hai header `Authorization` và `X-CSRF-TOKEN`.

### 3.4. Rate Limiting
- `POST /api/auth/login`: giới hạn **5 yêu cầu / 15 phút** theo phân vùng IP băm HMAC-SHA256 (`429 RATE_LIMIT_EXCEEDED`).
- `POST /api/auth/refresh`: giới hạn **15 yêu cầu / 5 phút** theo phân vùng IP băm HMAC-SHA256 (`429 RATE_LIMIT_EXCEEDED`).

## 4. Danh sách API Endpoints & DTO (BE0 + BE1)

| Method | Endpoint | Phân quyền | CSRF | Mô tả |
|---|---|---|---|---|
| `GET` | `/health/live` | Anonymous | Không | Kiểm tra tiến trình sống |
| `GET` | `/health/ready` | Anonymous | Không | Kiểm tra kết nối SQL Server |
| `GET` | `/api/auth/csrf` | Anonymous | Không | Phát hành antiforgery cookie và `requestToken` |
| `POST` | `/api/auth/login` | Anonymous | **Bắt buộc** | Đăng nhập, trả `accessToken` (`Bearer`, `900s`) + `user` và đặt refresh cookie |
| `POST` | `/api/auth/refresh` | Anonymous (Refresh Cookie) | **Bắt buộc** | Rotate refresh cookie và phát hành `accessToken` mới |
| `POST` | `/api/auth/logout` | Anonymous (Idempotent) | **Bắt buộc** | Thu hồi refresh token hiện hành (nếu có) và xóa refresh cookie |
| `POST` | `/api/auth/logout-all` | `Authenticated` (Bearer) | Không | Thu hồi mọi refresh token của user, xoay `SecurityStamp` và xóa refresh cookie |
| `GET` | `/api/auth/me` | `Authenticated` (Bearer) | Không | Trả `AuthenticatedUserDto` tối giản (`id`, `email`, `displayName`, `roles`, `lastLoginAt`) |
| `POST` | `/api/admin/hosts` | `AdminOnly` (Bearer) | Không | Admin tạo tài khoản `HOST` (`email`, `displayName`, `initialPassword`) |
| `POST` | `/api/admin/hosts/{hostId}/lock` | `AdminOnly` (Bearer) | Không | Admin khóa `HOST`, thu hồi refresh token và vô hiệu hóa JWT hiện hành |
| `POST` | `/api/admin/hosts/{hostId}/unlock` | `AdminOnly` (Bearer) | Không | Admin mở khóa `HOST` và đặt lại bộ đếm đăng nhập sai |

### 4.1. Swagger usage (Chỉ bật trong môi trường `Development`)

Swagger UI (`/swagger`) và tài liệu OpenAPI v1 (`/swagger/v1/swagger.json`) chỉ được kích hoạt khi `ASPNETCORE_ENVIRONMENT=Development`:

1. **Bước 1 — Lấy CSRF token (`GET /api/auth/csrf`):** Thực thi trên kết nối HTTPS và sao chép `data.requestToken`.
2. **Bước 2 — Đăng nhập (`POST /api/auth/login`):** Điền `X-CSRF-TOKEN`, `email` và mật khẩu SmartInvite; sao chép `data.accessToken` từ JSON phản hồi (trình duyệt tự nhận refresh cookie `__Host-SmartInvite.Refresh`).
3. **Bước 3 — Ủy quyền Bearer trên Swagger UI:** Bấm nút **Authorize** ở góc trên Swagger UI, dán giá trị `<accessToken>` (không cần gõ tiền tố `Bearer `) vào scheme **`Bearer`** rồi bấm **Authorize**.
4. **Bước 4 — Gọi các API Bearer (`GET /api/auth/me`, `POST /api/admin/hosts/*`, `POST /api/auth/logout-all`):** Gọi trực tiếp mà không cần điền `X-CSRF-TOKEN`.
5. **Bước 5 — Làm mới hoặc Đăng xuất (`POST /api/auth/refresh`, `POST /api/auth/logout`):** Điền `X-CSRF-TOKEN` để rotate hoặc thu hồi refresh cookie.

## 5. Thiết lập Môi trường Cục bộ & Bảo mật Biến Môi trường

Không lưu mật khẩu, khóa ký JWT hay chuỗi kết nối thật vào mã nguồn hoặc `appsettings*.json`. Mọi cache `.NET` / `NuGet` / `TEMP` đặt trong thư mục backend root:

```powershell
$backendRoot = "E:\Code\smartinviteBE"

New-Item -ItemType Directory -Force -Path `
  (Join-Path $backendRoot ".dotnet-home"), `
  (Join-Path $backendRoot ".nuget\packages"), `
  (Join-Path $backendRoot ".tmp") | Out-Null

$env:DOTNET_CLI_HOME = Join-Path $backendRoot ".dotnet-home"
$env:NUGET_PACKAGES = Join-Path $backendRoot ".nuget\packages"
$env:TEMP = Join-Path $backendRoot ".tmp"
$env:TMP = Join-Path $backendRoot ".tmp"

# Bắt buộc cấu hình khóa ký JWT tối thiểu 32 random bytes trước khi chạy API:
$env:Jwt__SigningKey = "<set-strong-32-plus-random-byte-key-at-runtime>"

Set-Location $backendRoot
```

### Cấu hình Admin Bootstrap (tùy chọn theo process)
Mặc định `BootstrapAdmin:Enabled = false`. Khi cần khởi tạo tài khoản `ADMIN` đầu tiên trên cơ sở dữ liệu **đã chạy migration**:

```powershell
$env:BootstrapAdmin__Enabled = "true"
$env:BootstrapAdmin__Email = "admin@example.invalid"
$env:BootstrapAdmin__Password = "<set-strong-password-at-runtime>"
$env:BootstrapAdmin__DisplayName = "System Administrator"
```

## 6. Chiến lược Migration & Quy tắc An toàn SQL Server Test Database

- Hai migration của BE1:
  1. `20261031182859_InitialIdentity` — Tạo 7 bảng chuẩn ASP.NET Core Identity cùng các cột mở rộng `DisplayName`, `CreatedAt`, `LastLoginAt` trên `AspNetUsers`.
  2. `20261101080317_AddRefreshTokens` — Tạo bảng `RefreshTokens` (lưu `TokenHash` `SHA-256` hex, `FamilyId`, vòng đời rotation/revocation, khóa ngoại cascade tới `AspNetUsers`, unique index `TokenHash` và các index truy vấn).
- Trước khi áp dụng migration hoặc chạy SQL Server integration tests, tên database (`Database` / `Initial Catalog`) **bắt buộc kết thúc bằng `_Test`** (ví dụ `SmartInvite_BE1_Test`) và vượt qua `SqlServerConnectionSafetyGuard`.

```powershell
dotnet tool restore --configfile .\NuGet.Config

dotnet tool run dotnet-ef migrations list `
  --project .\src\SmartInvite.Infrastructure\SmartInvite.Infrastructure.csproj `
  --startup-project .\src\SmartInvite.Api\SmartInvite.Api.csproj `
  --context ApplicationDbContext

dotnet tool run dotnet-ef migrations has-pending-model-changes `
  --project .\src\SmartInvite.Infrastructure\SmartInvite.Infrastructure.csproj `
  --startup-project .\src\SmartInvite.Api\SmartInvite.Api.csproj `
  --context ApplicationDbContext
```

## 7. Build, Kiểm thử và Định dạng Mã nguồn

```powershell
dotnet restore .\SmartInvite.sln --configfile .\NuGet.Config
dotnet build .\SmartInvite.sln --no-restore --configuration Release
dotnet test .\SmartInvite.sln --no-build --configuration Release --logger "console;verbosity=normal"
dotnet format .\SmartInvite.sln --verify-no-changes --no-restore
```
