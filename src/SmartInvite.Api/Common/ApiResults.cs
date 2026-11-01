using System.Diagnostics;
using SmartInvite.Domain.Common;

namespace SmartInvite.Api.Common;

public sealed record ApiEnvelope<T>(T Data);

public static class ApiResults
{
    private static readonly IReadOnlyDictionary<string, string[]> EmptyFields =
        new Dictionary<string, string[]>();

    public static IResult FromError(Error error, HttpContext httpContext)
    {
        var statusCode = MapStatusCode(error.Code);
        var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;

        var envelope = new ErrorEnvelope(new ErrorDetails(
            Code: error.Code,
            Message: error.Message,
            Fields: error.Fields ?? EmptyFields,
            TraceId: traceId));

        return Results.Json(envelope, statusCode: statusCode);
    }

    public static Task WriteErrorAsync(
        HttpContext httpContext,
        int statusCode,
        string code,
        string message,
        IReadOnlyDictionary<string, string[]>? fields = null,
        CancellationToken cancellationToken = default)
    {
        var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;

        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.ContentType = "application/json";

        var envelope = new ErrorEnvelope(new ErrorDetails(
            Code: code,
            Message: message,
            Fields: fields ?? EmptyFields,
            TraceId: traceId));

        return httpContext.Response.WriteAsJsonAsync(envelope, cancellationToken);
    }

    public static int MapStatusCode(string errorCode) =>
        errorCode switch
        {
            ErrorCodes.ValidationError => StatusCodes.Status400BadRequest,
            ErrorCodes.InvalidHostOperation => StatusCodes.Status400BadRequest,
            ErrorCodes.CsrfValidationFailed => StatusCodes.Status400BadRequest,
            ErrorCodes.InvalidCredentials => StatusCodes.Status401Unauthorized,
            ErrorCodes.AuthenticationRequired => StatusCodes.Status401Unauthorized,
            ErrorCodes.InvalidRefreshToken => StatusCodes.Status401Unauthorized,
            ErrorCodes.RefreshTokenReused => StatusCodes.Status401Unauthorized,
            ErrorCodes.Forbidden => StatusCodes.Status403Forbidden,
            ErrorCodes.HostNotFound => StatusCodes.Status404NotFound,
            ErrorCodes.EmailAlreadyExists => StatusCodes.Status409Conflict,
            ErrorCodes.ConcurrencyConflict => StatusCodes.Status409Conflict,
            ErrorCodes.RateLimitExceeded => StatusCodes.Status429TooManyRequests,
            ErrorCodes.TokenConfigurationInvalid => StatusCodes.Status500InternalServerError,
            _ => StatusCodes.Status500InternalServerError
        };
}
