# ADR 001: Sử dụng Secure Cookie Authentication trên ASP.NET Core Identity

- **Trạng thái:** Đã thay thế bởi [ADR 002](002-jwt-bearer-and-refresh-cookie-authentication.md) (Phase BE1 JWT Migration — 2026-11-01)
- **Ngày:** 2026-10-31 (cập nhật 2026-11-01)

## 1. Bối cảnh

SmartInvite cần cơ chế xác thực an toàn bằng Email và Mật khẩu cho hai vai trò quản trị trên web (`ADMIN` và `HOST`), đồng thời cho phép vô hiệu hóa ngay lập tức phiên đăng nhập hiện hành khi Admin khóa tài khoản Host. Khách mời mở thiệp công khai sử dụng bearer token một mục đích được băm SHA-256 ở các phase sau và không sử dụng tài khoản đăng nhập.

## 2. Quyết định

1. **Chọn Secure Cookie Authentication trên nền ASP.NET Core Identity (`Guid` key):**
   - Cookie tên `__Host-SmartInvite.Auth` với `HttpOnly=true`, `SecurePolicy=Always`, `SameSite=Lax`, `Path=/`, không cấu hình `Domain`, `SlidingExpiration=true`, thời hạn `8 giờ`.
   - `ApplicationUser` giữ mô hình tối giản (`DisplayName`, `CreatedAt`, `LastLoginAt`), không tách bảng hồ sơ phụ và không sử dụng số điện thoại trong nghiệp vụ.
   - Do BE1 chưa triển khai luồng gửi/xác minh email, hệ thống cấu hình nhất quán `SignIn.RequireConfirmedEmail = false` và giữ `EmailConfirmed = false` khi khởi tạo tài khoản để phản ánh trung thực trạng thái xác minh.
   - Kiểm tra tức thời `SecurityStamp` (`ValidationInterval = TimeSpan.Zero`) kết hợp trạng thái **Identity Lockout** ở phía server: khi `ADMIN` khóa `HOST` (`LockoutEnabled = true`, `LockoutEnd = DateTimeOffset.MaxValue`) hoặc mở khóa `HOST` (`LockoutEnd = null`, `AccessFailedCount = 0`), hệ thống xoay `SecurityStamp` để thu hồi ngay các cookie phiên cũ.
2. **Không dùng cơ chế bearer token lưu phía trình duyệt:**
   - Tránh rủi ro đánh cắp token dài hạn qua XSS trên trình duyệt.
   - Không phát sinh độ phức tạp của danh sách thu hồi token hoặc cơ chế xoay vòng token phụ trong giai đoạn MVP.
3. **Giảm thiểu rủi ro CSRF (CSRF Mitigation):**
   - Triển khai endpoint `GET /api/auth/csrf` phát hành antiforgery cookie `__Host-SmartInvite.Antiforgery` (`HttpOnly=true`, `Secure=Always`, `SameSite=Lax`, `Path=/`) và trả `requestToken`.
   - Mọi phương thức thay đổi trạng thái (`POST`, `PUT`, `PATCH`, `DELETE`) bắt buộc gửi kèm header `X-CSRF-TOKEN` hợp lệ.
   - Kết hợp cấu hình CORS chặt chẽ theo danh sách trắng `Cors:AllowedOrigins` (không dùng wildcard origin).

## 3. Đánh đổi (Trade-offs)

- **Ưu điểm:**
  - Trình duyệt tự động cách ly cookie xác thực khỏi JavaScript (`HttpOnly`) và chỉ truyền qua HTTPS (`__Host-` prefix + `Secure`).
  - Thu hồi phiên đăng nhập tức thời trên server khi `ADMIN` khóa tài khoản `HOST`.
- **Hạn chế khi Frontend và API khác origin/site:**
  - Với `SameSite=Lax`, để trình duyệt gửi cookie trên các lệnh gọi `fetch`/`XHR` kèm `credentials: "include"`, Frontend và API cần nằm cùng **registrable domain (same-site)** (ví dụ `smartinvite.example` và `api.smartinvite.example`, hoặc định tuyến chung qua reverse proxy Caddy cùng origin).
  - Nếu triển khai hoàn toàn khác site (cross-site domain độc lập), chính sách chặn third-party cookie của trình duyệt hiện đại sẽ cản trở cookie xác thực.

## 4. Điều kiện xem xét lại chiến lược xác thực

Chỉ xem xét bổ sung hoặc chuyển đổi chiến lược xác thực trong các trường hợp sau:
1. Phát triển ứng dụng di động native (iOS/Android) hoặc tích hợp máy-tới-máy (M2M API) không chạy trên mô hình cookie trình duyệt.
2. Kiến trúc triển khai bắt buộc đặt Frontend và Backend trên hai domain hoàn toàn khác site mà không thể định tuyến qua reverse proxy cùng site.
3. Khối lượng truy cập thực tế vượt ngưỡng khiến việc xác thực trạng thái phiên qua SQL Server cần bổ sung tầng phân tán đã được đo đạc và phê duyệt.
