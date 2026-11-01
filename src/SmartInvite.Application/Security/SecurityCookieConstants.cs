namespace SmartInvite.Application.Security;

public static class SecurityCookieConstants
{
    public const string RefreshCookieName = "__Host-SmartInvite.Refresh";
    public const string RefreshCookiePath = "/";
    public const string AntiforgeryCookieName = "__Host-SmartInvite.Antiforgery";
    public const string AntiforgeryCookiePath = "/";
    public const string CsrfHeaderName = "X-CSRF-TOKEN";
}
