using System.Diagnostics;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using SmartInvite.Api.Common;
using SmartInvite.Domain.Common;

namespace SmartInvite.Api.Extensions;

public sealed class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;

        switch (exception)
        {
            case AntiforgeryValidationException:
                _logger.LogWarning(
                    "CSRF validation exception handled. Method: {Method}, Path: {Path}, TraceId: {TraceId}",
                    httpContext.Request.Method,
                    httpContext.Request.Path,
                    traceId);

                await ApiResults.WriteErrorAsync(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    ErrorCodes.CsrfValidationFailed,
                    "Xác thực CSRF thất bại. Vui lòng lấy token mới và thử lại.",
                    cancellationToken: cancellationToken);
                return true;

            case BadHttpRequestException:
                _logger.LogWarning(
                    "Invalid HTTP request payload rejected. Method: {Method}, Path: {Path}, TraceId: {TraceId}",
                    httpContext.Request.Method,
                    httpContext.Request.Path,
                    traceId);

                await ApiResults.WriteErrorAsync(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    ErrorCodes.ValidationError,
                    "Định dạng dữ liệu yêu cầu không hợp lệ.",
                    cancellationToken: cancellationToken);
                return true;

            case DbUpdateConcurrencyException:
                _logger.LogWarning(
                    "Database concurrency conflict handled. Method: {Method}, Path: {Path}, TraceId: {TraceId}",
                    httpContext.Request.Method,
                    httpContext.Request.Path,
                    traceId);

                await ApiResults.WriteErrorAsync(
                    httpContext,
                    StatusCodes.Status409Conflict,
                    ErrorCodes.ConcurrencyConflict,
                    "Dữ liệu đã bị thay đổi đồng thời. Vui lòng tải lại và thử lại.",
                    cancellationToken: cancellationToken);
                return true;

            default:
                _logger.LogError(
                    exception,
                    "Unhandled exception occurred. TraceId: {TraceId}",
                    traceId);

                await ApiResults.WriteErrorAsync(
                    httpContext,
                    StatusCodes.Status500InternalServerError,
                    ErrorCodes.InternalError,
                    "Đã xảy ra lỗi không mong muốn",
                    cancellationToken: cancellationToken);
                return true;
        }
    }
}
