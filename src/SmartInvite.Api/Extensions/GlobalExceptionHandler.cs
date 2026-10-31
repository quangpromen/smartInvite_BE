using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;
using SmartInvite.Api.Common;

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

        _logger.LogError(
            exception,
            "Unhandled exception occurred. TraceId: {TraceId}",
            traceId);

        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
        httpContext.Response.ContentType = "application/json";

        var errorDetails = new ErrorDetails(
            Code: "INTERNAL_ERROR",
            Message: "Đã xảy ra lỗi không mong muốn",
            Fields: new Dictionary<string, string[]>(),
            TraceId: traceId);

        var response = new ErrorEnvelope(errorDetails);

        await httpContext.Response.WriteAsJsonAsync(response, cancellationToken);

        return true;
    }
}

