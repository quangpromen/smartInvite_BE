using Microsoft.OpenApi;
using SmartInvite.Api.OpenApi;

namespace SmartInvite.Api.Extensions;

public static class OpenApiExtensions
{
    public const string DocumentName = "v1";
    public const string DocumentTitle = "SmartInvite API";
    public const string DocumentVersion = "v1";
    public const string OpenApiJsonRoute = "/swagger/v1/swagger.json";
    public const string SwaggerUiRoutePrefix = "swagger";
    public const string BearerSecuritySchemeName = "Bearer";

    public static IServiceCollection AddApiOpenApi(this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();

        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc(DocumentName, new OpenApiInfo
            {
                Title = DocumentTitle,
                Version = DocumentVersion,
                Description = BuildDocumentDescription()
            });

            options.AddSecurityDefinition(BearerSecuritySchemeName, new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description =
                    "Nhập trực tiếp giá trị JWT accessToken nhận từ POST /api/auth/login hoặc POST /api/auth/refresh " +
                    "(chỉ dán chuỗi JWT, KHÔNG gõ tiền tố 'Bearer ' vì Swagger UI tự động thêm). " +
                    "Không bao giờ lưu signing key, mật khẩu hoặc token thật vào mã nguồn hay tệp cấu hình."
            });

            options.OperationFilter<AuthorizationOperationFilter>();
            options.OperationFilter<CsrfHeaderOperationFilter>();
            options.SchemaFilter<ContractSchemaFilter>();
        });

        return services;
    }

    public static WebApplication UseApiOpenApi(this WebApplication app)
    {
        if (!app.Environment.IsDevelopment())
        {
            return app;
        }

        app.UseSwagger(options =>
        {
            options.RouteTemplate = "swagger/{documentName}/swagger.json";
        });

        app.UseSwaggerUI(options =>
        {
            options.RoutePrefix = SwaggerUiRoutePrefix;
            options.DocumentTitle = "SmartInvite API — BE1 Identity & JWT Bearer Swagger UI";
            options.SwaggerEndpoint(OpenApiJsonRoute, "SmartInvite API v1 (BE1 Identity & JWT)");
            options.DisplayRequestDuration();
        });

        return app;
    }

    private static string BuildDocumentDescription() =>
        """
        **Phase BE1 — Simplified Identity, JWT Bearer Authentication & Refresh Cookie Rotation API** (ASP.NET Core Identity + Short-Lived JWT Bearer + HttpOnly Refresh Cookie + Metadata CSRF).

        ### Quy trình thử nghiệm API trong Swagger UI (yêu cầu HTTPS hợp lệ)
        1. **Lấy CSRF token:** Gọi `GET /api/auth/csrf` để trình duyệt nhận cookie `__Host-SmartInvite.Antiforgery` và sao chép giá trị `data.requestToken`.
        2. **Đăng nhập:** Gọi `POST /api/auth/login` với `email`, `password` (mật khẩu tài khoản SmartInvite, **không phải** mật khẩu Google/Gmail) và điền `requestToken` vào header `X-CSRF-TOKEN`. Phản hồi JSON trả về `data.accessToken` (JWT ngắn hạn) và trình duyệt nhận cookie `__Host-SmartInvite.Refresh` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`).
        3. **Ủy quyền Bearer trong Swagger UI:** Nhấn nút **Authorize**, dán giá trị `data.accessToken` (không gõ thêm chữ `Bearer `) rồi xác nhận.
        4. **Gọi các API Bearer (không cần CSRF):** Gọi `GET /api/auth/me`, `POST /api/auth/logout-all`, hoặc các API quản trị `POST /api/admin/hosts`, `POST /api/admin/hosts/{hostId}/lock`, `POST /api/admin/hosts/{hostId}/unlock` (khi đăng nhập bằng tài khoản `ADMIN`).
        5. **Làm mới access token:** Khi JWT hết hạn, gọi `POST /api/auth/refresh` kèm header `X-CSRF-TOKEN` để xoay vòng refresh cookie và nhận `data.accessToken` mới.
        6. **Đăng xuất:** Gọi `POST /api/auth/logout` kèm header `X-CSRF-TOKEN` để thu hồi refresh token hiện hành, hoặc `POST /api/auth/logout-all` với Bearer JWT để thu hồi toàn bộ phiên của tài khoản.
        """;
}
