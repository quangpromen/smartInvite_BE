using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SmartInvite.Api.Common;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;

namespace SmartInvite.IntegrationTests.Common;

public sealed class TestSessionClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly HttpClient _httpClient;
    private readonly Dictionary<string, StoredCookie> _cookies = new(StringComparer.Ordinal);
    private readonly string _remoteIp;

    public TestSessionClient(WebApplicationFactory<Program> factory, string remoteIp = "127.0.0.1")
    {
        _httpClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        _remoteIp = remoteIp;
    }

    public string? AccessToken { get; set; }

    public IReadOnlyDictionary<string, string> Cookies =>
        _cookies.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Value, StringComparer.Ordinal);

    public void SetCookie(string name, string value, string path = "/")
    {
        _cookies[name] = new StoredCookie(value, path);
    }

    public async Task<(string RequestToken, HttpResponseMessage Response)> FetchCsrfTokenAsync()
    {
        var response = await SendAsync(HttpMethod.Get, "/api/auth/csrf");
        var payload = await response.Content.ReadFromJsonAsync<ApiEnvelope<CsrfTokenDto>>(JsonOptions);
        return (payload!.Data.RequestToken, response);
    }

    public async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        object? jsonBody = null,
        string? csrfToken = null,
        string? bearerToken = null,
        Action<HttpRequestMessage>? configure = null)
    {
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Add(CustomWebApplicationFactory.TestRemoteIpHeader, _remoteIp);

        var matchingCookies = _cookies
            .Where(kvp => PathMatches(path, kvp.Value.Path))
            .Select(kvp => $"{kvp.Key}={kvp.Value.Value}")
            .ToArray();

        if (matchingCookies.Length > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", matchingCookies));
        }

        var effectiveBearer = bearerToken ?? AccessToken;
        if (!string.IsNullOrWhiteSpace(effectiveBearer))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                AuthTokenConstants.BearerTokenType,
                effectiveBearer);
        }

        if (csrfToken is not null)
        {
            request.Headers.Add(SecurityCookieConstants.CsrfHeaderName, csrfToken);
        }

        if (jsonBody is not null)
        {
            request.Content = JsonContent.Create(jsonBody);
        }

        configure?.Invoke(request);

        var response = await _httpClient.SendAsync(request);
        CaptureCookies(response);
        return response;
    }

    private static bool PathMatches(string requestPathAndQuery, string cookiePath)
    {
        if (string.IsNullOrEmpty(cookiePath) || cookiePath == "/")
        {
            return true;
        }

        var qIndex = requestPathAndQuery.IndexOf('?');
        var reqPath = qIndex >= 0 ? requestPathAndQuery[..qIndex] : requestPathAndQuery;
        var normalizedCookiePath = cookiePath.TrimEnd('/');

        if (reqPath.Equals(normalizedCookiePath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return reqPath.StartsWith(normalizedCookiePath + "/", StringComparison.OrdinalIgnoreCase);
    }

    private void CaptureCookies(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
        {
            return;
        }

        foreach (var rawHeader in setCookieHeaders)
        {
            var segments = rawHeader.Split(';', StringSplitOptions.TrimEntries);
            if (segments.Length == 0)
            {
                continue;
            }

            var nameValue = segments[0];
            var eqIndex = nameValue.IndexOf('=');
            if (eqIndex <= 0)
            {
                continue;
            }

            var cookieName = nameValue[..eqIndex];
            var cookieValue = nameValue[(eqIndex + 1)..];
            var cookiePath = "/";
            var hasExplicitPath = false;
            var hasSecure = false;
            var hasDomain = false;

            foreach (var attr in segments.Skip(1))
            {
                if (attr.StartsWith("path=", StringComparison.OrdinalIgnoreCase))
                {
                    cookiePath = attr["path=".Length..];
                    hasExplicitPath = true;
                }
                else if (attr.Equals("secure", StringComparison.OrdinalIgnoreCase))
                {
                    hasSecure = true;
                }
                else if (attr.StartsWith("domain=", StringComparison.OrdinalIgnoreCase))
                {
                    hasDomain = true;
                }
            }

            if (cookieName.StartsWith("__Host-", StringComparison.Ordinal))
            {
                var isHttpsOrigin = string.Equals(
                    response.RequestMessage?.RequestUri?.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase);

                if (!isHttpsOrigin || !hasSecure || hasDomain || !hasExplicitPath || cookiePath != "/")
                {
                    throw new InvalidOperationException(
                        $"Trình duyệt từ chối cookie tiền tố '__Host-' không hợp lệ '{cookieName}' (Https={isHttpsOrigin}, Secure={hasSecure}, HasDomain={hasDomain}, ExplicitPath={hasExplicitPath}, Path='{cookiePath}').");
                }
            }

            var isExpired = string.IsNullOrEmpty(cookieValue) ||
                            segments.Skip(1).Any(attr =>
                                (attr.StartsWith("expires=", StringComparison.OrdinalIgnoreCase) &&
                                 DateTimeOffset.TryParse(attr["expires=".Length..], out var exp) &&
                                 exp <= DateTimeOffset.UtcNow) ||
                                (attr.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase) &&
                                 int.TryParse(attr["max-age=".Length..], out var maxAge) &&
                                 maxAge <= 0));

            if (isExpired)
            {
                _cookies.Remove(cookieName);
            }
            else
            {
                _cookies[cookieName] = new StoredCookie(cookieValue, cookiePath);
            }
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    private sealed record StoredCookie(string Value, string Path);
}
