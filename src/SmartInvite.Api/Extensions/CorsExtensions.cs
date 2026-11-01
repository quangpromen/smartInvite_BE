using Microsoft.AspNetCore.Cors.Infrastructure;
using SmartInvite.Application.Security;

namespace SmartInvite.Api.Extensions;

public static class CorsExtensions
{
    public const string PolicyName = "SmartInviteCors";

    public static IServiceCollection AddApiCors(this IServiceCollection services)
    {
        services.AddCors();

        services.AddOptions<CorsOptions>()
            .Configure<IConfiguration>((options, configuration) =>
            {
                var rawOrigins = configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
                var normalizedOrigins = ValidateAndNormalizeOrigins(rawOrigins);

                options.AddPolicy(PolicyName, policy =>
                {
                    if (normalizedOrigins.Length == 0)
                    {
                        return;
                    }

                    policy
                        .WithOrigins(normalizedOrigins)
                        .AllowCredentials()
                        .WithHeaders(
                            "Authorization",
                            "Content-Type",
                            "Accept",
                            SecurityCookieConstants.CsrfHeaderName,
                            "X-Requested-With")
                        .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
                });
            })
            .ValidateOnStart();

        return services;
    }

    public static string[] ValidateAndNormalizeOrigins(IEnumerable<string> configuredOrigins)
    {
        var results = new List<string>();

        foreach (var rawOrigin in configuredOrigins)
        {
            if (string.IsNullOrWhiteSpace(rawOrigin))
            {
                continue;
            }

            var trimmed = rawOrigin.Trim().TrimEnd('/');

            if (trimmed.Contains('*', StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "Cấu hình Cors:AllowedOrigins không được phép chứa ký tự đại diện ('*') khi dùng xác thực cookie.");
            }

            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
                !string.IsNullOrEmpty(uri.PathAndQuery.Trim('/')) ||
                !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new InvalidOperationException(
                    $"Giá trị origin trong Cors:AllowedOrigins không hợp lệ: '{trimmed}'.");
            }

            results.Add(trimmed);
        }

        return results.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
