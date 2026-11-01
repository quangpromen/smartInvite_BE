using Microsoft.AspNetCore.Mvc;
using SmartInvite.Api.Common;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;

namespace SmartInvite.Api.Endpoints;

public static class AdminHostEndpoints
{
    public static IEndpointRouteBuilder MapAdminHostEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/admin/hosts")
            .WithTags("AdminHosts")
            .RequireAuthorization(AuthorizationPolicies.AdminOnly);

        group.MapPost(string.Empty, CreateHostAsync)
            .WithName("CreateHost")
            .WithSummary("Khởi tạo tài khoản HOST mới (ADMIN only, Bearer JWT)")
            .WithDescription(
                "Tạo tài khoản người dùng mới và gán duy nhất vai trò HOST trong database transaction. " +
                "Yêu cầu xác thực JWT Bearer bằng tài khoản có vai trò ADMIN.")
            .Produces<ApiEnvelope<HostSummaryDto>>(StatusCodes.Status201Created)
            .Produces<ErrorEnvelope>(StatusCodes.Status400BadRequest)
            .Produces<ErrorEnvelope>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorEnvelope>(StatusCodes.Status403Forbidden)
            .Produces<ErrorEnvelope>(StatusCodes.Status409Conflict)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        group.MapPost("/{hostId}/lock", LockHostAsync)
            .WithName("LockHost")
            .WithSummary("Khóa vĩnh viễn tài khoản HOST và thu hồi phiên hiện hành (ADMIN only, Bearer JWT)")
            .WithDescription(
                "Đặt LockoutEnd = MaxValue, thu hồi các refresh token đang hoạt động và xoay SecurityStamp để vô hiệu hóa tức thời các JWT access token đã cấp cho HOST mục tiêu (`hostId` định dạng GUID). " +
                "Không cho phép tự khóa chính mình hoặc khóa tài khoản ADMIN.")
            .Produces<ApiEnvelope<HostSummaryDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status400BadRequest)
            .Produces<ErrorEnvelope>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorEnvelope>(StatusCodes.Status403Forbidden)
            .Produces<ErrorEnvelope>(StatusCodes.Status404NotFound)
            .Produces<ErrorEnvelope>(StatusCodes.Status409Conflict)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        group.MapPost("/{hostId}/unlock", UnlockHostAsync)
            .WithName("UnlockHost")
            .WithSummary("Mở khóa tài khoản HOST và đặt lại bộ đếm đăng nhập sai (ADMIN only, Bearer JWT)")
            .WithDescription(
                "Xóa LockoutEnd, đặt lại AccessFailedCount = 0 và xoay SecurityStamp cho tài khoản HOST mục tiêu (`hostId` định dạng GUID) " +
                "mà không khôi phục token cũ, không đặt lại mật khẩu và không tự động đăng nhập.")
            .Produces<ApiEnvelope<HostSummaryDto>>(StatusCodes.Status200OK)
            .Produces<ErrorEnvelope>(StatusCodes.Status400BadRequest)
            .Produces<ErrorEnvelope>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorEnvelope>(StatusCodes.Status403Forbidden)
            .Produces<ErrorEnvelope>(StatusCodes.Status404NotFound)
            .Produces<ErrorEnvelope>(StatusCodes.Status409Conflict)
            .Produces<ErrorEnvelope>(StatusCodes.Status500InternalServerError);

        return endpoints;
    }

    private static async Task<IResult> CreateHostAsync(
        [FromBody] CreateHostRequest? request,
        HttpContext httpContext,
        IAdminHostService adminHostService,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        var result = await adminHostService.CreateHostAsync(request, cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        return Results.Created(
            $"/api/admin/hosts/{result.Value.Id}",
            new ApiEnvelope<HostSummaryDto>(result.Value));
    }

    private static async Task<IResult> LockHostAsync(
        string hostId,
        HttpContext httpContext,
        IAdminHostService adminHostService,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        if (!TryParseHostId(hostId, out var parsedHostId, out var parseError))
        {
            return ApiResults.FromError(parseError, httpContext);
        }

        var result = await adminHostService.LockHostAsync(parsedHostId, cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        return Results.Ok(new ApiEnvelope<HostSummaryDto>(result.Value));
    }

    private static async Task<IResult> UnlockHostAsync(
        string hostId,
        HttpContext httpContext,
        IAdminHostService adminHostService,
        CancellationToken cancellationToken)
    {
        httpContext.Response.Headers.CacheControl = "no-store";

        if (!TryParseHostId(hostId, out var parsedHostId, out var parseError))
        {
            return ApiResults.FromError(parseError, httpContext);
        }

        var result = await adminHostService.UnlockHostAsync(parsedHostId, cancellationToken);
        if (result.IsFailure)
        {
            return ApiResults.FromError(result.Error, httpContext);
        }

        return Results.Ok(new ApiEnvelope<HostSummaryDto>(result.Value));
    }

    private static bool TryParseHostId(string rawHostId, out Guid parsedHostId, out Error error)
    {
        if (Guid.TryParse(rawHostId, out parsedHostId))
        {
            error = Error.None;
            return true;
        }

        error = Error.Validation(
            "Mã định danh Host không hợp lệ.",
            new Dictionary<string, string[]>
            {
                ["hostId"] = ["Mã định danh Host phải là định dạng GUID hợp lệ."]
            });
        return false;
    }
}
