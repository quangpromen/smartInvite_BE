using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using SmartInvite.Api.Common;
using SmartInvite.Api.Extensions;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;

namespace SmartInvite.Api.Endpoints;

public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/auth")
            .WithTags("Authentication");

        group.MapGet("/csrf", IssueCsrfToken)
            .AllowAnonymous()
            .WithName("IssueCsrfToken")
            .WithSummary("Phát hành antiforgery cookie và CSRF request token (Anonymous)")
            .WithDescription(
                "Phát hành cookie __Host-SmartInvite.Antiforgery (HttpOnly, Secure, SameSite=Lax, Path=/) và trả về data.requestToken " +
                "để đính kèm vào header X-CSRF-TOKEN khi gọi các endpoint sử dụng refresh cookie (login, refresh, logout).")
            .Produces<ApiEnvelope<CsrfTokenDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        group.MapPost("/login", LoginAsync)
            .AllowAnonymous()
            .RequireSmartInviteCsrf()
            .RequireRateLimiting(RateLimitPolicies.Login)
            .WithName("Login")
            .WithSummary("Đăng nhập bằng email và mật khẩu SmartInvite, trả JWT Bearer và đặt refresh cookie (Anonymous, yêu cầu CSRF)")
            .WithDescription(
                "Xác thực tài khoản ADMIN hoặc HOST bằng mật khẩu SmartInvite (không phải mật khẩu Google/Gmail), " +
                "trả về JWT access token ngắn hạn trong JSON và đặt refresh token ngẫu nhiên vào cookie HttpOnly Secure __Host-SmartInvite.Refresh (Path=/api/auth). " +
                "Yêu cầu header X-CSRF-TOKEN hợp lệ; giới hạn tốc độ 5 yêu cầu / 15 phút theo phân vùng IP.")
            .Produces<ApiEnvelope<LoginResponseDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status400BadRequest)
            .Produces<ErrorEnvelope>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorEnvelope>(StatusCodes.Status409Conflict)
            .Produces<ErrorEnvelope>(StatusCodes.Status429TooManyRequests)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        group.MapPost("/refresh", RefreshAsync)
            .AllowAnonymous()
            .RequireSmartInviteCsrf()
            .RequireRateLimiting(RateLimitPolicies.Refresh)
            .WithName("RefreshAccessToken")
            .WithSummary("Xoay vòng refresh cookie và phát hành JWT access token mới (Anonymous, yêu cầu CSRF)")
            .WithDescription(
                "Đọc refresh token từ cookie __Host-SmartInvite.Refresh, thực hiện rotation trong SQL Server transaction với cơ chế phát hiện reuse theo token family, " +
                "đặt refresh cookie mới và trả về JWT access token ngắn hạn mới. Yêu cầu header X-CSRF-TOKEN hợp lệ; giới hạn tốc độ 15 yêu cầu / 5 phút theo phân vùng IP.")
            .Produces<ApiEnvelope<RefreshResponseDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status400BadRequest)
            .Produces<ErrorEnvelope>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorEnvelope>(StatusCodes.Status429TooManyRequests)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        group.MapPost("/logout", LogoutAsync)
            .AllowAnonymous()
            .RequireSmartInviteCsrf()
            .WithName("Logout")
            .WithSummary("Thu hồi refresh token hiện hành và xóa refresh cookie (Anonymous idempotent, yêu cầu CSRF)")
            .WithDescription(
                "Thu hồi refresh token tương ứng với cookie __Host-SmartInvite.Refresh hiện hành (nếu có) và xóa refresh cookie trên trình duyệt. " +
                "Hoạt động idempotent mà không yêu cầu JWT access token còn hiệu lực; bắt buộc gửi kèm header X-CSRF-TOKEN hợp lệ.")
            .Produces<ApiEnvelope<LogoutResponseDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status400BadRequest)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        group.MapPost("/logout-all", LogoutAllAsync)
            .RequireAuthorization(AuthorizationPolicies.Authenticated)
            .WithName("LogoutAll")
            .WithSummary("Thu hồi toàn bộ refresh token và vô hiệu hóa mọi access token của tài khoản (Bearer Authenticated)")
            .WithDescription(
                "Yêu cầu header Authorization: Bearer <accessToken>. Thu hồi toàn bộ refresh token đang hoạt động của người dùng, " +
                "xoay SecurityStamp để vô hiệu hóa tức thời các JWT access token cũ và xóa refresh cookie hiện hành mà không đặt lại mật khẩu.")
            .Produces<ApiEnvelope<LogoutResponseDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorEnvelope>(StatusCodes.Status409Conflict)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        group.MapGet("/me", GetCurrentUserAsync)
            .RequireAuthorization(AuthorizationPolicies.Authenticated)
            .WithName("GetCurrentUser")
            .WithSummary("Lấy thông tin tài khoản hiện tại từ JWT Bearer (Bearer Authenticated)")
            .WithDescription(
                "Trả về hồ sơ người dùng tối giản (id, email, displayName, roles, lastLoginAt) tương ứng với JWT Bearer access token hợp lệ.")
            .Produces<ApiEnvelope<AuthenticatedUserDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        return endpoints;
    }

    private static IResult IssueCsrfToken(
        HttpContext httpContext,
        IAntiforgery antiforgery)
    {
        httpContext.Response.Headers.CacheControl = "no-store, no-cache, max-age=0";

        var tokens = antiforgery.GetAndStoreCookieFlowTokens(httpContext);
        var response = new ApiEnvelope<CsrfTokenDto>(new CsrfTokenDto(tokens.RequestToken!));

        return Results.Ok(response);
    }

    private static async Task<IResult> LoginAsync(
        [FromBody] LoginRequest? request,
        HttpContext httpContext,
        IAuthSessionService authenticationService,
        IDateTimeProvider dateTimeProvider,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        var result = await authenticationService.LoginAsync(request, cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        RefreshCookieService.AppendRefreshCookie(
            httpContext,
            result.Value.RawRefreshToken,
            dateTimeProvider.UtcNow,
            result.Value.RefreshTokenExpiresAt);

        return Results.Ok(new ApiEnvelope<LoginResponseDto>(result.Value.Response));
    }

    private static async Task<IResult> RefreshAsync(
        HttpContext httpContext,
        IAuthSessionService authenticationService,
        IDateTimeProvider dateTimeProvider,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        var rawRefreshToken = RefreshCookieService.ReadRefreshCookie(httpContext);
        var result = await authenticationService.RefreshAsync(rawRefreshToken, cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        RefreshCookieService.AppendRefreshCookie(
            httpContext,
            result.Value.RawRefreshToken,
            dateTimeProvider.UtcNow,
            result.Value.RefreshTokenExpiresAt);

        return Results.Ok(new ApiEnvelope<RefreshResponseDto>(result.Value.Response));
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext httpContext,
        IAuthSessionService authenticationService,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        var rawRefreshToken = RefreshCookieService.ReadRefreshCookie(httpContext);
        var result = await authenticationService.LogoutAsync(rawRefreshToken, cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        RefreshCookieService.DeleteRefreshCookie(httpContext);

        return Results.Ok(new ApiEnvelope<LogoutResponseDto>(result.Value));
    }

    private static async Task<IResult> LogoutAllAsync(
        HttpContext httpContext,
        IAuthSessionService authenticationService,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        var result = await authenticationService.LogoutAllAsync(cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        RefreshCookieService.DeleteRefreshCookie(httpContext);

        return Results.Ok(new ApiEnvelope<LogoutResponseDto>(result.Value));
    }

    private static async Task<IResult> GetCurrentUserAsync(
        HttpContext httpContext,
        IAuthSessionService authenticationService,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        var result = await authenticationService.GetCurrentUserAsync(cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        return Results.Ok(new ApiEnvelope<AuthenticatedUserDto>(result.Value));
    }
}
