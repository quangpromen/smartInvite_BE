# SmartInvite Backend

Backend API cho nền tảng thiệp cưới và thiệp sự kiện số SmartInvite.

## 1. Mục đích

Cung cấp REST API hiệu năng cao, an toàn và có khả năng mở rộng cho SmartInvite:
- Quản trị sự kiện (Events), nhiều mẫu thiệp (CardDesigns) trong cùng sự kiện.
- Quản lý khách mời theo phạm vi sự kiện, gán mẫu thiệp và cá nhân hóa thiệp mời.
- Phát hành thiệp mời với bearer token bảo mật (băm SHA-256), ghi nhận phản hồi RSVP và check-in QR bảo mật.
- Báo cáo thống kê thời gian thực và phân quyền đa cấp (Admin, Host, Staff).

## 2. Kiến trúc dự án (Modular Monolith / Clean Architecture)

Dự án được cấu trúc theo mô hình Clean Architecture:

```text
E:\Code\smartinviteBE
├── SmartInvite.sln
├── Directory.Build.props
├── Directory.Packages.props
├── NuGet.Config
├── .editorconfig
├── .gitignore
├── src/
│   ├── SmartInvite.Domain/          # Enterprise business rules, domain types, kết quả/lỗi nền tảng
│   ├── SmartInvite.Application/     # Use cases, interfaces (ICurrentUser, IDateTimeProvider), business abstractions
│   ├── SmartInvite.Infrastructure/  # Entity Framework Core, SQL Server DbContext, service implementations
│   └── SmartInvite.Api/             # Web API endpoints, Program composition, middleware, error handling, health checks
└── tests/
    ├── SmartInvite.UnitTests/       # Kiểm thử đơn vị cho domain/application components
    ├── SmartInvite.ArchitectureTests/# Kiểm thử kiến trúc phụ thuộc (NetArchTest)
    └── SmartInvite.IntegrationTests/# Kiểm thử tích hợp WebApplicationFactory (Health, Error handling)
```

## 3. Quy tắc chiều phụ thuộc (Dependency Direction)

```text
Domain
  ↑
Application
  ↑
Infrastructure
  ↑
Api
```

- `SmartInvite.Domain` không phụ thuộc vào bất kỳ project nào khác.
- `SmartInvite.Application` chỉ phụ thuộc vào `SmartInvite.Domain`.
- `SmartInvite.Infrastructure` phụ thuộc vào `SmartInvite.Application`.
- `SmartInvite.Api` phụ thuộc vào `SmartInvite.Application` và `SmartInvite.Infrastructure`.
- Tuyệt đối không để rò rỉ phụ thuộc ngược chiều hoặc rò rỉ tầng Infrastructure vào Domain/Application.

## 4. Yêu cầu môi trường

- **.NET 10 SDK** (hỗ trợ target framework `net10.0`).
- SQL Server (chuẩn bị cho phase BE1 trở đi; phase BE0 chưa yêu cầu kết nối thật).

## 5. Thiết lập biến môi trường cục bộ (PowerShell)

Mọi trạng thái .NET CLI, NuGet packages và tệp tạm phải nằm bên trong thư mục backend root:

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
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_NOLOGO = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
```

Khi cần chạy thử với database thật trong môi trường dev, truyền connection string qua biến môi trường của process hiện tại:

```powershell
$env:ConnectionStrings__SmartInviteDatabase = "<your-local-sql-server-connection-string>"
```

## 6. Lệnh thao tác

Tất cả lệnh chạy từ thư mục `E:\Code\smartinviteBE` trong session PowerShell đã nạp biến môi trường ở trên:

### Restore dependencies
```powershell
dotnet restore .\SmartInvite.sln --configfile .\NuGet.Config
```

### Build dự án (Release)
```powershell
dotnet build .\SmartInvite.sln --no-restore --configuration Release
```

### Chạy kiểm thử tự động
```powershell
dotnet test .\SmartInvite.sln --no-build --configuration Release
```

### Kiểm tra định dạng mã nguồn
```powershell
dotnet format .\SmartInvite.sln --verify-no-changes --no-restore
```

### Chạy Web API
```powershell
dotnet run --project .\src\SmartInvite.Api\SmartInvite.Api.csproj
```

## 7. Health Check Endpoints

- **Liveness:** `GET /health/live`  
  Kiểm tra tiến trình API có đang sống hay không. Không phụ thuộc vào cơ sở dữ liệu. Trả về `200 OK` với `{"status":"Healthy"}`.
- **Readiness:** `GET /health/ready`  
  Kiểm tra tính sẵn sàng của các phụ thuộc (SQL Server). Nếu chưa cấu hình chuỗi kết nối, endpoint trả về trạng thái `Degraded` kèm mô tả rõ ràng mà không làm crash ứng dụng.

## 8. Ghi chú về Phase BE0 (Architecture Scaffolding)

- **Chưa có Business API:** Phase BE0 chỉ khởi tạo kiến trúc, DI container, DbContext nền tảng, Global Error Handling và Health Check. Không tạo mock/fake business endpoints để tránh sai lệch đặc tả.
- **Chưa có EF Core Migration:** Chưa sinh migration hay chạy `database update` vì domain models và Identity sẽ được thẩm định và tạo chính thức ở Phase BE1.
- **Không dùng PostgreSQL:** Toàn bộ backend mới sử dụng Microsoft SQL Server và Entity Framework Core. Các migration PostgreSQL trong repo frontend chỉ mang tính chất tham chiếu lịch sử.

## 9. Lộ trình phát triển backend (Roadmap BE1 – BE7)

- **BE1 — SQL Server and Identity:** Cấu hình EF Core models/configurations, tạo SQL Server migrations ban đầu, tích hợp ASP.NET Core Identity, cơ chế xác thực Host/Admin và ownership policies.
- **BE2 — Events and CardDesigns:** Nghiệp vụ vòng đời sự kiện, quản lý nhiều CardDesigns trong một sự kiện (bản nháp draft vs bản công bố published, đặt mặc định, nhân bản, lưu trữ).
- **BE3 — Guests and Categories:** Quản lý danh mục khách, CRUD khách mời, gán/chuyển mẫu thiệp trong sự kiện, cá nhân hóa lời mời.
- **BE4 — Invitations and RSVP:** Phát hành token thiệp mời (băm SHA-256), giải quyết link công khai, ghi nhận phản hồi RSVP (idempotent upsert), kiểm tra deadline.
- **BE5 — Analytics and Dashboards:** Thống kê lượt xem yêu cầu (request) và lượt xem người thật (beacon), tổng hợp chỉ số Host và Admin dashboard.
- **BE6 — Check-in and Hardening:** Check-in QR bảo mật (HMAC/version), bảo vệ chống quét trùng lặp, audit log, bảo mật CSV export và security headers.
- **BE7 — FE Integration and Release Readiness:** Tích hợp API adapter vào frontend repository thay thế mock repository, kiểm thử luồng end-to-end, diễn tập sao lưu/phục hồi.

