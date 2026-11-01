using Microsoft.OpenApi;
using SmartInvite.Api.Common;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Application.Auth;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SmartInvite.Api.OpenApi;

public sealed class ContractSchemaFilter : ISchemaFilter
{
    public void Apply(IOpenApiSchema schema, SchemaFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(context);

        if (schema is not OpenApiSchema concreteSchema)
        {
            return;
        }

        if (context.Type == typeof(LoginRequest))
        {
            concreteSchema.Description = "Thông tin đăng nhập tài khoản SmartInvite (ADMIN hoặc HOST).";
            SetPropertyDescription(concreteSchema, "email", "Địa chỉ email đăng nhập của tài khoản SmartInvite.");
            SetPropertyDescription(
                concreteSchema,
                "password",
                "Mật khẩu tài khoản SmartInvite (không phải mật khẩu tài khoản Google/Gmail).");
        }
        else if (context.Type == typeof(LoginResponseDto))
        {
            concreteSchema.Description = "Kết quả đăng nhập thành công chứa JWT Bearer access token ngắn hạn và hồ sơ người dùng tối giản.";
            SetPropertyDescription(concreteSchema, "accessToken", "Chuỗi JWT Bearer access token ngắn hạn dùng cho header Authorization.");
            SetPropertyDescription(concreteSchema, "tokenType", "Loại token xác thực (Bearer).");
            SetPropertyDescription(concreteSchema, "expiresInSeconds", "Thời hạn hiệu lực của access token tính bằng giây.");
            SetPropertyDescription(concreteSchema, "user", "Hồ sơ tối giản của người dùng vừa đăng nhập.");
        }
        else if (context.Type == typeof(RefreshResponseDto))
        {
            concreteSchema.Description = "Kết quả làm mới phiên thành công chứa JWT Bearer access token mới.";
            SetPropertyDescription(concreteSchema, "accessToken", "Chuỗi JWT Bearer access token ngắn hạn mới.");
            SetPropertyDescription(concreteSchema, "tokenType", "Loại token xác thực (Bearer).");
            SetPropertyDescription(concreteSchema, "expiresInSeconds", "Thời hạn hiệu lực của access token mới tính bằng giây.");
        }
        else if (context.Type == typeof(CreateHostRequest))
        {
            concreteSchema.Description = "Dữ liệu khởi tạo tài khoản HOST mới bởi ADMIN.";
            SetPropertyDescription(concreteSchema, "email", "Địa chỉ email duy nhất của tài khoản HOST.");
            SetPropertyDescription(concreteSchema, "displayName", "Tên hiển thị của HOST (bắt buộc, tối đa 150 ký tự).");
            SetPropertyDescription(
                concreteSchema,
                "initialPassword",
                "Mật khẩu khởi tạo đáp ứng chính sách bảo mật của SmartInvite.");
        }
        else if (context.Type == typeof(AuthenticatedUserDto))
        {
            concreteSchema.Description = "Thông tin hồ sơ người dùng tối giản của tài khoản đã xác thực.";
            SetPropertyDescription(concreteSchema, "id", "Định danh GUID của người dùng.");
            SetPropertyDescription(concreteSchema, "email", "Địa chỉ email của người dùng.");
            SetPropertyDescription(concreteSchema, "displayName", "Tên hiển thị của người dùng.");
            SetPropertyDescription(concreteSchema, "roles", "Danh sách vai trò hệ thống hiện hành (ADMIN, HOST).");
            SetPropertyDescription(concreteSchema, "lastLoginAt", "Thời điểm đăng nhập thành công gần nhất (UTC).");
        }
        else if (context.Type == typeof(HostSummaryDto))
        {
            concreteSchema.Description = "Thông tin tóm tắt tối giản của tài khoản HOST dành cho ADMIN.";
            SetPropertyDescription(concreteSchema, "id", "Định danh GUID của tài khoản HOST.");
            SetPropertyDescription(concreteSchema, "email", "Địa chỉ email của tài khoản HOST.");
            SetPropertyDescription(concreteSchema, "displayName", "Tên hiển thị của tài khoản HOST.");
            SetPropertyDescription(concreteSchema, "isLocked", "Trạng thái tài khoản đang bị khóa (tạm thời hoặc bởi ADMIN).");
            SetPropertyDescription(concreteSchema, "createdAt", "Thời điểm khởi tạo tài khoản (UTC).");
            SetPropertyDescription(concreteSchema, "lastLoginAt", "Thời điểm đăng nhập thành công gần nhất (UTC, có thể null).");
        }
        else if (context.Type == typeof(CsrfTokenDto))
        {
            concreteSchema.Description = "Token chống giả mạo yêu cầu liên trang (CSRF) dùng cho header X-CSRF-TOKEN.";
            SetPropertyDescription(
                concreteSchema,
                "requestToken",
                "Giá trị antiforgery request token cần gửi trong header X-CSRF-TOKEN khi gọi các endpoint sử dụng refresh cookie.");
        }
        else if (context.Type == typeof(LogoutResponseDto))
        {
            concreteSchema.Description = "Kết quả thu hồi phiên đăng nhập.";
            SetPropertyDescription(concreteSchema, "signedOut", "Xác nhận phiên làm mới đã được đăng xuất và xóa refresh cookie.");
        }
        else if (context.Type == typeof(ErrorEnvelope))
        {
            concreteSchema.Description = "Phong bì lỗi chuẩn hóa của SmartInvite API.";
        }
        else if (context.Type == typeof(ErrorDetails))
        {
            concreteSchema.Description = "Chi tiết mã lỗi, thông điệp, lỗi theo trường dữ liệu và mã truy vết.";
        }
    }

    private static void SetPropertyDescription(OpenApiSchema parentSchema, string propertyName, string description)
    {
        if (parentSchema.Properties is null ||
            !parentSchema.Properties.TryGetValue(propertyName, out var propertySchema) ||
            propertySchema is not OpenApiSchema concreteProperty)
        {
            return;
        }

        concreteProperty.Description = description;
        concreteProperty.Example = null;
    }
}
