using SmartInvite.Application.Security;

namespace SmartInvite.Api.Common;

public static class RefreshCookieService
{
    public static CookieOptions BuildAppendOptions(DateTimeOffset utcNow, DateTimeOffset expiresAtUtc)
    {
        var maxAge = expiresAtUtc > utcNow
            ? expiresAtUtc - utcNow
            : TimeSpan.Zero;

        return new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = SecurityCookieConstants.RefreshCookiePath,
            Domain = null,
            MaxAge = maxAge,
            Expires = expiresAtUtc,
            IsEssential = true
        };
    }

    public static CookieOptions BuildDeleteOptions() =>
        new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = SecurityCookieConstants.RefreshCookiePath,
            Domain = null,
            IsEssential = true
        };

    public static string? ReadRefreshCookie(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        return httpContext.Request.Cookies.TryGetValue(SecurityCookieConstants.RefreshCookieName, out var rawToken)
            ? rawToken
            : null;
    }

    public static void AppendRefreshCookie(
        HttpContext httpContext,
        string rawRefreshToken,
        DateTimeOffset utcNow,
        DateTimeOffset expiresAtUtc)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(rawRefreshToken);

        httpContext.Response.Cookies.Append(
            SecurityCookieConstants.RefreshCookieName,
            rawRefreshToken,
            BuildAppendOptions(utcNow, expiresAtUtc));
    }

    public static void DeleteRefreshCookie(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        httpContext.Response.Cookies.Delete(
            SecurityCookieConstants.RefreshCookieName,
            BuildDeleteOptions());
    }
}

