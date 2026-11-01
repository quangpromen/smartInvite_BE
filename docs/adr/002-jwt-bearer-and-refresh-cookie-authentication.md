# ADR 002: Chuyển sang JWT Bearer Access Token kết hợp HttpOnly Secure Refresh Cookie

- **Trạng thái:** Đã phê duyệt (Phase BE1 — JWT Migration Remediation)
- **Ngày:** 2026-11-01
- **Thay thế:** [ADR 001: Sử dụng Secure Cookie Authentication trên ASP.NET Core Identity](001-cookie-authentication.md)

## 1. Bối cảnh

SmartInvite BE1 cần chuyển cơ chế xác thực truy cập API từ Cookie Authentication (`__Host-SmartInvite.Auth`) sang **JWT Bearer Authentication** để tách bạch rõ luồng gọi API nghiệp vụ (`Authorization: Bearer <accessToken>`) và luồng duy trì phiên đăng nhập, đồng thời giữ nguyên toàn bộ mô hình định danh tối giản trên **ASP.NET Core Identity** (`ApplicationUser`, `IdentityRole<Guid>`, `ADMIN` / `HOST`, password hashing, temporary lockout) và khả năng thu hồi tức thời hiệu lực access token khi `ADMIN` khóa tài khoản `HOST`.

## 2. Quyết định kiến trúc

1. **Access Token — JWT Bearer ngắn hạn (`15 phút` mặc định):**
   - Ký bằng `HMAC-SHA256` (`HS256`) với khóa đối xứng tối thiểu `32` bytes ngẫu nhiên đọc từ biến môi trường tiến trình `Jwt__SigningKey` (fail-fast khi khởi động nếu thiếu, quá ngắn hoặc entropy thấp; tuyệt đối không lưu khóa thật trong `appsettings*.json`).
   - Trả về trong JSON response của `POST /api/auth/login` và `POST /api/auth/refresh`; không bao giờ lưu access token vào cookie, database hoặc log.
   - Chỉ mang tập claim tối thiểu: `sub`, `email`, `name` (`DisplayName`), `role`, `jti`, `iat`, `nbf`, `exp`, `iss` (`SmartInvite.Api`), `aud` (`SmartInvite.Web`) và `sst` (băm `SHA-256` hex của `SecurityStamp` — không đưa `SecurityStamp` thô vào JWT).
   - Bật đầy đủ kiểm tra chữ ký, `iss`, `aud`, `exp`/`nbf` (`ClockSkew = 30s`, `SaveToken = false`, `MapInboundClaims = false`, chỉ chấp nhận `HS256`, từ chối `alg=none`) và luôn trả JSON `ErrorEnvelope` cho `401`/`403`.

2. **Thu hồi tức thời JWT khi Admin khóa/mở khóa Host hoặc người dùng `logout-all`:**
   - Trong `JwtBearerEvents.OnTokenValidated`, `AccessTokenStateValidator` đối chiếu `sub` với `ApplicationUser` trong SQL Server: từ chối ngay (`401`) nếu user không tồn tại, đang chịu Identity Lockout (`LockoutEnabled && LockoutEnd > UtcNow`) hoặc băm `SHA-256(SecurityStamp)` hiện tại không khớp hằng thời gian (`CryptographicOperations.FixedTimeEquals`) với claim `sst`.
   - Khi `ADMIN` gọi `POST /api/admin/hosts/{hostId}/lock` (hoặc `/unlock`), hệ thống xoay `SecurityStamp` (và thu hồi toàn bộ refresh token đang hoạt động của Host khi lock). Do đó mọi JWT phát hành trước đó mất hiệu lực ngay ở request kế tiếp và không tự sống lại sau khi unlock.

3. **Refresh Token — Chuỗi ngẫu nhiên mật mã trong HttpOnly Secure Cookie (`7 ngày` mặc định):**
   - Không dùng JWT làm refresh token; sinh tối thiểu `64` random bytes từ `RandomNumberGenerator` mã hóa `Base64Url`.
   - Chỉ truyền cho trình duyệt qua cookie `__Host-SmartInvite.Refresh` (`HttpOnly=true`, `Secure=Always`, `SameSite=Lax`, `Path=/api/auth`, `Domain=null`); không bao giờ trả refresh token trong JSON hoặc ghi ra log.
   - Bảng `RefreshTokens` trong SQL Server chỉ lưu băm `SHA-256` hex (`TokenHash`, `varchar(64)`, unique index) cùng `FamilyId`, `CreatedAt`, `ExpiresAt`, `RotatedAt`, `RevokedAt`, `ReplacedByTokenId`, `RevokedReason`.
   - **Rotation, Concurrency & Reuse Detection:** Mỗi lần `POST /api/auth/refresh` hợp lệ thực hiện cập nhật điều kiện nguyên tử trong SQL Server transaction để đảm bảo tối đa 1 request đồng thời thành công; nếu phát hiện một refresh token đã rotate/revoke bị gửi lại, toàn bộ `FamilyId` bị thu hồi ngay lập tức (`RevokedReason = "ReuseDetected"`) và trả lỗi tổng quát `401 INVALID_REFRESH_TOKEN`.

4. **CSRF theo Endpoint Metadata, CORS và Rate Limiting:**
   - Bảo vệ CSRF (`__Host-SmartInvite.Antiforgery` + header `X-CSRF-TOKEN` qua `.RequireSmartInviteCsrf()`) chỉ áp dụng cho các endpoint thao tác dựa trên cookie (`POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout`).
   - Các endpoint xác thực thuần bằng `Authorization: Bearer` (`GET /api/auth/me`, `POST /api/auth/logout-all`, `/api/admin/hosts/*`) không yêu cầu CSRF header để thuận tiện cho Bearer API client và Swagger UI.
   - CORS allowlist cho phép `AllowCredentials()` kèm hai header `Authorization` và `X-CSRF-TOKEN` (cấm wildcard `*`).
   - Rate Limiting theo phân vùng IP băm HMAC-SHA256: `5 requests / 15 phút` cho `/api/auth/login` và `15 requests / 5 phút` cho `/api/auth/refresh`.

