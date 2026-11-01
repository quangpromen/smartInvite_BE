using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using SmartInvite.Api.Common;
using SmartInvite.Domain.Common;

namespace SmartInvite.Api.Extensions;

public static class RateLimitPolicies
{
    public const string Login = "auth-login";
    public const string Refresh = "auth-refresh";
}

public static class RateLimitingExtensions
{
    private static readonly byte[] EphemeralIpHashKey = RandomNumberGenerator.GetBytes(32);

    public static IServiceCollection AddApiRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.AddPolicy(RateLimitPolicies.Login, httpContext =>
            {
                var partitionKey = BuildPrivacySafePartitionKey(RateLimitPolicies.Login, httpContext);

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(15),
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });

            options.AddPolicy(RateLimitPolicies.Refresh, httpContext =>
            {
                var partitionKey = BuildPrivacySafePartitionKey(RateLimitPolicies.Refresh, httpContext);

                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 15,
                        Window = TimeSpan.FromMinutes(5),
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });

            options.OnRejected = async (context, cancellationToken) =>
            {
                var httpContext = context.HttpContext;
                var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;

                var logger = httpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("SmartInvite.RateLimiting");

                logger.LogWarning(
                    "Rate limit exceeded. Method: {Method}, Path: {Path}, TraceId: {TraceId}",
                    httpContext.Request.Method,
                    httpContext.Request.Path,
                    traceId);

                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
                    httpContext.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
                }

                await ApiResults.WriteErrorAsync(
                    httpContext,
                    StatusCodes.Status429TooManyRequests,
                    ErrorCodes.RateLimitExceeded,
                    "Quá nhiều yêu cầu. Vui lòng thử lại sau ít phút.",
                    cancellationToken: cancellationToken);
            };
        });

        return services;
    }

    private static string BuildPrivacySafePartitionKey(string endpointName, HttpContext httpContext)
    {
        var remoteIp = httpContext.Connection.RemoteIpAddress;
        if (remoteIp is null)
        {
            return $"{endpointName}:local";
        }

        var normalizedIp = remoteIp.IsIPv4MappedToIPv6
            ? remoteIp.MapToIPv4().ToString()
            : remoteIp.ToString();

        var hashBytes = HMACSHA256.HashData(EphemeralIpHashKey, Encoding.UTF8.GetBytes(normalizedIp));
        var hashHex = Convert.ToHexString(hashBytes.AsSpan(0, 16));

        return $"{endpointName}:{hashHex}";
    }
}
