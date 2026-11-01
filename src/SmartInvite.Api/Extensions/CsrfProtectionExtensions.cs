using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using SmartInvite.Api.Common;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;

namespace SmartInvite.Api.Extensions;

public interface ISmartInviteCsrfMetadata;

public sealed class RequireSmartInviteCsrfMetadata : ISmartInviteCsrfMetadata;

public static class CsrfProtectionExtensions
{
    private static readonly ClaimsPrincipal CookieFlowAntiforgeryPrincipal = new(new ClaimsIdentity());

    public static IServiceCollection AddApiCsrfProtection(this IServiceCollection services)
    {
        services.AddAntiforgery(options =>
        {
            options.HeaderName = SecurityCookieConstants.CsrfHeaderName;
            options.Cookie.Name = SecurityCookieConstants.AntiforgeryCookieName;
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.Path = SecurityCookieConstants.AntiforgeryCookiePath;
            options.Cookie.Domain = null;
        });

        return services;
    }

    public static AntiforgeryTokenSet GetAndStoreCookieFlowTokens(
        this IAntiforgery antiforgery,
        HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(antiforgery);
        ArgumentNullException.ThrowIfNull(httpContext);

        var originalUser = httpContext.User;
        try
        {
            httpContext.User = CookieFlowAntiforgeryPrincipal;
            return antiforgery.GetAndStoreTokens(httpContext);
        }
        finally
        {
            httpContext.User = originalUser;
        }
    }

    public static async Task ValidateCookieFlowRequestAsync(
        this IAntiforgery antiforgery,
        HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(antiforgery);
        ArgumentNullException.ThrowIfNull(httpContext);

        var originalUser = httpContext.User;
        try
        {
            httpContext.User = CookieFlowAntiforgeryPrincipal;
            await antiforgery.ValidateRequestAsync(httpContext);
        }
        finally
        {
            httpContext.User = originalUser;
        }
    }

    public static TBuilder RequireSmartInviteCsrf<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.WithMetadata(new RequireSmartInviteCsrfMetadata());
        return builder;
    }

    public static IApplicationBuilder UseCsrfProtection(this IApplicationBuilder app) =>
        app.UseMiddleware<CsrfProtectionMiddleware>();
}

public sealed class CsrfProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<CsrfProtectionMiddleware> _logger;

    public CsrfProtectionMiddleware(
        RequestDelegate next,
        IAntiforgery antiforgery,
        ILogger<CsrfProtectionMiddleware> logger)
    {
        _next = next;
        _antiforgery = antiforgery;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext httpContext)
    {
        if (!EndpointRequiresCsrf(httpContext.GetEndpoint()))
        {
            await _next(httpContext);
            return;
        }

        try
        {
            await _antiforgery.ValidateCookieFlowRequestAsync(httpContext);
        }
        catch (AntiforgeryValidationException)
        {
            var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;

            _logger.LogWarning(
                "CSRF validation rejected cookie-protected request. Method: {Method}, Path: {Path}, TraceId: {TraceId}",
                httpContext.Request.Method,
                httpContext.Request.Path,
                traceId);

            await ApiResults.WriteErrorAsync(
                httpContext,
                StatusCodes.Status400BadRequest,
                ErrorCodes.CsrfValidationFailed,
                "Xác thực CSRF thất bại. Vui lòng lấy token mới và thử lại.",
                cancellationToken: httpContext.RequestAborted);
            return;
        }

        await _next(httpContext);
    }

    public static bool EndpointRequiresCsrf(Endpoint? endpoint) =>
        endpoint?.Metadata.GetMetadata<ISmartInviteCsrfMetadata>() is not null;
}
