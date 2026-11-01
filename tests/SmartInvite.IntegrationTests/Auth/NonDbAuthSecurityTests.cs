using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SmartInvite.Api.Common;
using SmartInvite.Api.Extensions;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Identity;
using SmartInvite.Infrastructure.Persistence;
using SmartInvite.IntegrationTests.Common;
using Xunit;

namespace SmartInvite.IntegrationTests.Auth;

public class NonDbAuthSecurityTests : IClassFixture<CustomWebApplicationFactory>
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly CustomWebApplicationFactory _factory;

    public NonDbAuthSecurityTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task AuthenticationSchemes_ShouldRegisterJwtBearerOnly_WithoutLegacyCookieAccessScheme()
    {
        var schemeProvider = _factory.Services.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemes = (await schemeProvider.GetAllSchemesAsync()).ToArray();

        var bearerScheme = Assert.Single(schemes);
        Assert.Equal(JwtBearerDefaults.AuthenticationScheme, bearerScheme.Name);
        Assert.Equal(typeof(JwtBearerHandler), bearerScheme.HandlerType);

        var defaultAuth = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
        var defaultChallenge = await schemeProvider.GetDefaultChallengeSchemeAsync();
        var defaultForbid = await schemeProvider.GetDefaultForbidSchemeAsync();

        Assert.Equal(JwtBearerDefaults.AuthenticationScheme, defaultAuth?.Name);
        Assert.Equal(JwtBearerDefaults.AuthenticationScheme, defaultChallenge?.Name);
        Assert.Equal(JwtBearerDefaults.AuthenticationScheme, defaultForbid?.Name);

        var jwtBearerMonitor = _factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>();
        var jwtBearerOptions = jwtBearerMonitor.Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.False(jwtBearerOptions.SaveToken);
        Assert.False(jwtBearerOptions.MapInboundClaims);
        Assert.True(jwtBearerOptions.TokenValidationParameters.ValidateIssuer);
        Assert.True(jwtBearerOptions.TokenValidationParameters.ValidateAudience);
        Assert.True(jwtBearerOptions.TokenValidationParameters.ValidateLifetime);
        Assert.True(jwtBearerOptions.TokenValidationParameters.ValidateIssuerSigningKey);
        Assert.True(jwtBearerOptions.TokenValidationParameters.RequireExpirationTime);
        Assert.True(jwtBearerOptions.TokenValidationParameters.RequireSignedTokens);
        Assert.True(jwtBearerOptions.TokenValidationParameters.ClockSkew <= TimeSpan.FromSeconds(60));
        Assert.Equal([SecurityAlgorithms.HmacSha256], jwtBearerOptions.TokenValidationParameters.ValidAlgorithms);
    }

    [Fact]
    public async Task PersistenceModel_ShouldHaveZeroPendingModelChanges_AndExactTwoBe1Migrations()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        Assert.False(dbContext.Database.HasPendingModelChanges());

        var migrations = dbContext.Database.GetMigrations().ToArray();
        Assert.Equal(
            ["20261031182859_InitialIdentity", "20261101080317_AddRefreshTokens"],
            migrations);
    }

    [Theory]
    [InlineData("Development", "")]
    [InlineData("Production", "")]
    [InlineData("Production", "too-short-secret-key")]
    public async Task Startup_WhenJwtSigningKeyMissingOrTooShort_FailsFast_WithoutLeakingSigningKey(
        string environmentName,
        string invalidSigningKey)
    {
        var exception = await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            await using var invalidFactory = _factory.WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment(environmentName);
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Jwt:SigningKey"] = invalidSigningKey
                    });
                });
            });

            using var client = new TestSessionClient(invalidFactory, "198.51.100.90");
            _ = await client.SendAsync(HttpMethod.Get, "/health/live");
        });

        Assert.Contains("Jwt:SigningKey", exception.Message, StringComparison.Ordinal);
        if (!string.IsNullOrWhiteSpace(invalidSigningKey))
        {
            Assert.DoesNotContain(invalidSigningKey, exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task MissingOrInvalidBearerTokens_Return401JsonErrorEnvelope_AndLegacyAuthCookieIsIgnored()
    {
        using var client = new TestSessionClient(_factory, "198.51.100.1");

        // 1. Missing Bearer header
        var missingResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, missingResp.StatusCode);
        var missingEnvelope = await ReadErrorEnvelopeAsync(missingResp);
        Assert.Equal(ErrorCodes.AuthenticationRequired, missingEnvelope.Error.Code);
        Assert.False(string.IsNullOrWhiteSpace(missingEnvelope.Error.TraceId));

        // 2. Legacy __Host-SmartInvite.Auth cookie sent without Bearer token must NOT authenticate
        client.SetCookie("__Host-SmartInvite.Auth", "legacy-cookie-payload", "/");
        var legacyCookieResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, legacyCookieResp.StatusCode);

        // 3. Malformed Bearer token
        var malformedResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: "not-a-valid-jwt");
        Assert.Equal(HttpStatusCode.Unauthorized, malformedResp.StatusCode);
        Assert.Equal(ErrorCodes.AuthenticationRequired, (await ReadErrorEnvelopeAsync(malformedResp)).Error.Code);

        // 4. Wrong signature JWT
        var wrongKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var wrongSigJwt = CreateTestJwt(
            signingKey: wrongKey,
            issuer: "SmartInvite.Api",
            audience: "SmartInvite.Web",
            issuedAtUtc: DateTimeOffset.UtcNow,
            expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(15),
            role: RoleNames.Host);
        var wrongSigResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: wrongSigJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongSigResp.StatusCode);

        // 5. Wrong issuer JWT
        var wrongIssuerJwt = CreateTestJwt(
            signingKey: CustomWebApplicationFactory.TestJwtSigningKey,
            issuer: "Untrusted.Issuer",
            audience: "SmartInvite.Web",
            issuedAtUtc: DateTimeOffset.UtcNow,
            expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(15),
            role: RoleNames.Host);
        var wrongIssuerResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: wrongIssuerJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongIssuerResp.StatusCode);

        // 6. Wrong audience JWT
        var wrongAudienceJwt = CreateTestJwt(
            signingKey: CustomWebApplicationFactory.TestJwtSigningKey,
            issuer: "SmartInvite.Api",
            audience: "Untrusted.Audience",
            issuedAtUtc: DateTimeOffset.UtcNow,
            expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(15),
            role: RoleNames.Host);
        var wrongAudienceResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: wrongAudienceJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongAudienceResp.StatusCode);

        // 7. Expired JWT
        var pastTime = DateTimeOffset.UtcNow.AddMinutes(-20);
        var expiredJwt = CreateTestJwt(
            signingKey: CustomWebApplicationFactory.TestJwtSigningKey,
            issuer: "SmartInvite.Api",
            audience: "SmartInvite.Web",
            issuedAtUtc: pastTime,
            expiresAtUtc: pastTime.AddMinutes(15),
            role: RoleNames.Host);
        var expiredResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: expiredJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, expiredResp.StatusCode);

        // 8. Unsigned alg=none JWT must be rejected
        var algNoneHeader = Base64Url.EncodeToString("""{"alg":"none","typ":"JWT"}"""u8);
        var algNonePayload = Base64Url.EncodeToString(
            Encoding.UTF8.GetBytes($$"""{"sub":"{{Guid.NewGuid()}}","iss":"SmartInvite.Api","aud":"SmartInvite.Web","exp":{{DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds()}}}"""));
        var algNoneToken = $"{algNoneHeader}.{algNonePayload}.";
        var algNoneResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: algNoneToken);
        Assert.Equal(HttpStatusCode.Unauthorized, algNoneResp.StatusCode);
    }

    [Fact]
    public async Task GetCsrfToken_ShouldIssueAntiforgeryCookieWithStrictAttributes_WithoutAuthOrRefreshCookies()
    {
        using var client = new TestSessionClient(_factory, "198.51.100.2");

        var (requestToken, response) = await client.FetchCsrfTokenAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(string.IsNullOrWhiteSpace(requestToken));

        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var setCookies));
        var cookieList = setCookies.ToArray();

        var antiforgeryCookie = Assert.Single(cookieList, c =>
            c.StartsWith($"{SecurityCookieConstants.AntiforgeryCookieName}=", StringComparison.Ordinal));

        Assert.Contains("httponly", antiforgeryCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", antiforgeryCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", antiforgeryCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", antiforgeryCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", antiforgeryCookie, StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(cookieList, c =>
            c.StartsWith("__Host-SmartInvite.Auth=", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(cookieList, c =>
            c.StartsWith($"{SecurityCookieConstants.RefreshCookieName}=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CookieEndpoints_LoginRefreshAndLogout_RequireValidCsrfToken_AndReturn400WhenMissingOrInvalid()
    {
        using var missingClient = new TestSessionClient(_factory, "198.51.100.3");

        foreach (var (cookiePath, body) in new (string, object?)[]
        {
            ("/api/auth/login", new { email = "host@example.invalid", password = "TestPassword#1234" }),
            ("/api/auth/refresh", null),
            ("/api/auth/logout", null)
        })
        {
            var missingResponse = await missingClient.SendAsync(HttpMethod.Post, cookiePath, jsonBody: body);
            Assert.Equal(HttpStatusCode.BadRequest, missingResponse.StatusCode);

            var rawBody = await missingResponse.Content.ReadAsStringAsync();
            var missingEnvelope = JsonSerializer.Deserialize<ErrorEnvelope>(rawBody, JsonOptions);
            Assert.NotNull(missingEnvelope);
            Assert.Equal(ErrorCodes.CsrfValidationFailed, missingEnvelope.Error.Code);
            Assert.DoesNotContain("AntiforgeryValidationException", rawBody);
            Assert.DoesNotContain("StackTrace", rawBody);
        }

        using var invalidClient = new TestSessionClient(_factory, "198.51.100.31");
        _ = await invalidClient.FetchCsrfTokenAsync();

        foreach (var (cookiePath, body) in new (string, object?)[]
        {
            ("/api/auth/login", new { email = "host@example.invalid", password = "TestPassword#1234" }),
            ("/api/auth/refresh", null),
            ("/api/auth/logout", null)
        })
        {
            var invalidResponse = await invalidClient.SendAsync(
                HttpMethod.Post,
                cookiePath,
                jsonBody: body,
                csrfToken: "tampered-invalid-csrf-token");

            Assert.Equal(HttpStatusCode.BadRequest, invalidResponse.StatusCode);
            var invalidEnvelope = await ReadErrorEnvelopeAsync(invalidResponse);
            Assert.Equal(ErrorCodes.CsrfValidationFailed, invalidEnvelope.Error.Code);
        }

        // Valid CSRF on idempotent logout without refresh cookie succeeds and sends delete Set-Cookie
        using var validLogoutClient = new TestSessionClient(_factory, "198.51.100.32");
        var (validCsrf, _) = await validLogoutClient.FetchCsrfTokenAsync();
        var logoutResp = await validLogoutClient.SendAsync(HttpMethod.Post, "/api/auth/logout", csrfToken: validCsrf);
        Assert.Equal(HttpStatusCode.OK, logoutResp.StatusCode);
        Assert.True(logoutResp.Headers.TryGetValues("Set-Cookie", out var logoutSetCookies));
        var deletedRefreshCookie = Assert.Single(logoutSetCookies, c =>
            c.StartsWith($"{SecurityCookieConstants.RefreshCookieName}=", StringComparison.Ordinal));
        Assert.Contains("path=/api/auth", deletedRefreshCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", deletedRefreshCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", deletedRefreshCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", deletedRefreshCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BearerEndpoints_DoNotRequireCsrf_AndEnforceRoleAuthorizationWithRealJwtBearerHandler()
    {
        await using var stubFactory = CreateRealJwtNonDbFactory();
        var tokenService = stubFactory.Services.GetRequiredService<IAccessTokenService>();

        var adminToken = tokenService.CreateAccessToken(
            new AccessTokenSubject(
                StubActiveTokenStateValidator.AdminId,
                "admin@example.invalid",
                "System Admin",
                [RoleNames.Admin],
                "ADMIN-STAMP-1"),
            DateTimeOffset.UtcNow).AccessToken;

        var hostToken = tokenService.CreateAccessToken(
            new AccessTokenSubject(
                StubActiveTokenStateValidator.HostId,
                "host@example.invalid",
                "Host User",
                [RoleNames.Host],
                "HOST-STAMP-1"),
            DateTimeOffset.UtcNow).AccessToken;

        // 1. HOST calling Admin endpoints gets 403 JSON ErrorEnvelope (without needing CSRF)
        using var hostClient = new TestSessionClient(stubFactory, "198.51.100.40")
        {
            AccessToken = hostToken
        };

        var hostCreateResp = await hostClient.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new
            {
                email = "another@example.invalid",
                displayName = "Another Host",
                initialPassword = $"Host#{Guid.NewGuid():N}Aa1!"
            });
        Assert.Equal(HttpStatusCode.Forbidden, hostCreateResp.StatusCode);
        Assert.Equal(ErrorCodes.Forbidden, (await ReadErrorEnvelopeAsync(hostCreateResp)).Error.Code);

        var hostLockResp = await hostClient.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{Guid.NewGuid()}/lock");
        Assert.Equal(HttpStatusCode.Forbidden, hostLockResp.StatusCode);

        var hostUnlockResp = await hostClient.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{Guid.NewGuid()}/unlock");
        Assert.Equal(HttpStatusCode.Forbidden, hostUnlockResp.StatusCode);

        // HOST calling HostOnly endpoint succeeds
        var hostOnlyResp = await hostClient.SendAsync(HttpMethod.Get, "/internal/test-host-only");
        Assert.Equal(HttpStatusCode.OK, hostOnlyResp.StatusCode);

        // 2. ADMIN calling Bearer POST endpoints WITHOUT CSRF token succeeds!
        using var adminClient = new TestSessionClient(stubFactory, "198.51.100.41")
        {
            AccessToken = adminToken
        };

        var adminCreateResp = await adminClient.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new
            {
                email = "created@example.invalid",
                displayName = "Created Host",
                initialPassword = $"Host#{Guid.NewGuid():N}Aa1!"
            });
        Assert.Equal(HttpStatusCode.Created, adminCreateResp.StatusCode);

        var targetHostId = Guid.NewGuid();
        var adminLockResp = await adminClient.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{targetHostId}/lock");
        Assert.Equal(HttpStatusCode.OK, adminLockResp.StatusCode);

        var adminUnlockResp = await adminClient.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{targetHostId}/unlock");
        Assert.Equal(HttpStatusCode.OK, adminUnlockResp.StatusCode);

        var logoutAllResp = await adminClient.SendAsync(HttpMethod.Post, "/api/auth/logout-all");
        Assert.Equal(HttpStatusCode.OK, logoutAllResp.StatusCode);

        // ADMIN calling HostOnly endpoint gets 403 Forbidden
        var adminCallingHostOnly = await adminClient.SendAsync(HttpMethod.Get, "/internal/test-host-only");
        Assert.Equal(HttpStatusCode.Forbidden, adminCallingHostOnly.StatusCode);
    }

    [Fact]
    public async Task CorsConfiguration_AllowsConfiguredOriginWithCredentials_AllowsAuthorizationAndCsrfHeaders_AndRejectsWildcard()
    {
        using var defaultClient = new TestSessionClient(_factory, "198.51.100.4");
        var defaultPreflight = await defaultClient.SendAsync(
            HttpMethod.Options,
            "/api/auth/csrf",
            configure: req =>
            {
                req.Headers.Add("Origin", "https://untrusted.example.invalid");
                req.Headers.Add("Access-Control-Request-Method", "POST");
            });

        Assert.False(defaultPreflight.Headers.Contains("Access-Control-Allow-Origin"));

        await using var configuredFactory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Cors:AllowedOrigins:0"] = "https://app.smartinvite.invalid"
                });
            });
        });

        using var corsClient = new TestSessionClient(configuredFactory, "198.51.100.5");

        // Preflight for cookie-based refresh endpoint with X-CSRF-TOKEN
        var csrfPreflight = await corsClient.SendAsync(
            HttpMethod.Options,
            "/api/auth/refresh",
            configure: req =>
            {
                req.Headers.Add("Origin", "https://app.smartinvite.invalid");
                req.Headers.Add("Access-Control-Request-Method", "POST");
                req.Headers.Add("Access-Control-Request-Headers", $"{SecurityCookieConstants.CsrfHeaderName}, Content-Type");
            });

        Assert.True(csrfPreflight.Headers.TryGetValues("Access-Control-Allow-Origin", out var allowedOrigins));
        Assert.Equal(["https://app.smartinvite.invalid"], allowedOrigins);
        Assert.True(csrfPreflight.Headers.TryGetValues("Access-Control-Allow-Credentials", out var allowCreds));
        Assert.Equal(["true"], allowCreds);

        // Preflight for Bearer endpoint with Authorization header
        var bearerPreflight = await corsClient.SendAsync(
            HttpMethod.Options,
            "/api/admin/hosts",
            configure: req =>
            {
                req.Headers.Add("Origin", "https://app.smartinvite.invalid");
                req.Headers.Add("Access-Control-Request-Method", "POST");
                req.Headers.Add("Access-Control-Request-Headers", "Authorization, Content-Type");
            });

        Assert.True(bearerPreflight.Headers.TryGetValues("Access-Control-Allow-Headers", out var allowedHeaders));
        var joinedHeaders = string.Join(",", allowedHeaders);
        Assert.Contains("Authorization", joinedHeaders, StringComparison.OrdinalIgnoreCase);

        var disallowedPreflight = await corsClient.SendAsync(
            HttpMethod.Options,
            "/api/auth/login",
            configure: req =>
            {
                req.Headers.Add("Origin", "https://attacker.example.invalid");
                req.Headers.Add("Access-Control-Request-Method", "POST");
            });

        Assert.False(disallowedPreflight.Headers.Contains("Access-Control-Allow-Origin"));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using var wildcardFactory = _factory.WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Cors:AllowedOrigins:0"] = "*"
                    });
                });
            });
            using var wildcardClient = new TestSessionClient(wildcardFactory, "198.51.100.99");
            _ = await wildcardClient.SendAsync(HttpMethod.Get, "/health/live");
        });
    }

    [Fact]
    public async Task ProductionEnvironment_WhenServiceThrows_ShouldReturnUnifiedEnvelope_WithoutStackTrace()
    {
        await using var prodFactory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.ConfigureServices(services =>
            {
                services.AddScoped<IAuthSessionService, ThrowingAuthSessionService>();
            });
        });

        using var prodClient = new TestSessionClient(prodFactory, "198.51.100.6");
        var (csrfToken, _) = await prodClient.FetchCsrfTokenAsync();

        var response = await prodClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new { email = "host@example.invalid", password = "TestPassword#1234" },
            csrfToken: csrfToken);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);

        var rawBody = await response.Content.ReadAsStringAsync();
        var envelope = JsonSerializer.Deserialize<ErrorEnvelope>(rawBody, JsonOptions);

        Assert.NotNull(envelope);
        Assert.Equal(ErrorCodes.InternalError, envelope.Error.Code);
        Assert.DoesNotContain("SimulatedFailure", rawBody);
        Assert.DoesNotContain("InvalidOperationException", rawBody);
        Assert.DoesNotContain("StackTrace", rawBody);
    }

    [Fact]
    public async Task LoginAndRefreshRateLimiters_EnforceSeparateThresholds_PerPrivacySafeIpPartition()
    {
        using var loginLimitedClient = new TestSessionClient(_factory, "198.51.100.50");
        using var otherIpClient = new TestSessionClient(_factory, "198.51.100.51");

        var (csrfToken, _) = await loginLimitedClient.FetchCsrfTokenAsync();
        for (var i = 0; i < 5; i++)
        {
            var attempt = await loginLimitedClient.SendAsync(
                HttpMethod.Post,
                "/api/auth/login",
                new { email = "invalid-email", password = "x" },
                csrfToken: csrfToken);

            Assert.Equal(HttpStatusCode.BadRequest, attempt.StatusCode);
        }

        var sixthLoginAttempt = await loginLimitedClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new { email = "invalid-email", password = "x" },
            csrfToken: csrfToken);

        Assert.Equal(HttpStatusCode.TooManyRequests, sixthLoginAttempt.StatusCode);
        Assert.Equal(ErrorCodes.RateLimitExceeded, (await ReadErrorEnvelopeAsync(sixthLoginAttempt)).Error.Code);
        Assert.True(sixthLoginAttempt.Headers.Contains("Retry-After"));

        // Separate IP partition is unaffected
        var (otherCsrf, _) = await otherIpClient.FetchCsrfTokenAsync();
        var otherIpAttempt = await otherIpClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new { email = "invalid-email", password = "x" },
            csrfToken: otherCsrf);
        Assert.Equal(HttpStatusCode.BadRequest, otherIpAttempt.StatusCode);

        // Refresh rate limiter (15 requests / 5 minutes)
        using var refreshLimitedClient = new TestSessionClient(_factory, "198.51.100.52");
        var (refreshCsrf, _) = await refreshLimitedClient.FetchCsrfTokenAsync();
        for (var i = 0; i < 15; i++)
        {
            var refreshAttempt = await refreshLimitedClient.SendAsync(
                HttpMethod.Post,
                "/api/auth/refresh",
                csrfToken: refreshCsrf);
            Assert.Equal(HttpStatusCode.Unauthorized, refreshAttempt.StatusCode);
        }

        var sixteenthRefresh = await refreshLimitedClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/refresh",
            csrfToken: refreshCsrf);
        Assert.Equal(HttpStatusCode.TooManyRequests, sixteenthRefresh.StatusCode);
        Assert.Equal(ErrorCodes.RateLimitExceeded, (await ReadErrorEnvelopeAsync(sixteenthRefresh)).Error.Code);
    }

    [Fact]
    public async Task AnonymousRequests_ToBearerProtectedEndpoints_ShouldReturn401()
    {
        using var client = new TestSessionClient(_factory, "198.51.100.70");
        var hostId = Guid.NewGuid();

        var meResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me");
        var logoutAllResp = await client.SendAsync(HttpMethod.Post, "/api/auth/logout-all");
        var createHostResp = await client.SendAsync(HttpMethod.Post, "/api/admin/hosts", new { });
        var lockResp = await client.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{hostId}/lock");
        var unlockResp = await client.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{hostId}/unlock");
        var hostOnlyResp = await client.SendAsync(HttpMethod.Get, "/internal/test-host-only");

        Assert.Equal(HttpStatusCode.Unauthorized, meResp.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, logoutAllResp.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, createHostResp.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, lockResp.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unlockResp.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, hostOnlyResp.StatusCode);
    }

    [Fact]
    public async Task EndpointMetadata_MatchesExactCsrfAndAuthorizationBoundaries()
    {
        var endpointSources = _factory.Services.GetServices<EndpointDataSource>();
        var routeEndpoints = endpointSources
            .SelectMany(s => s.Endpoints)
            .OfType<RouteEndpoint>()
            .ToArray();

        Assert.DoesNotContain(routeEndpoints, e =>
            string.Equals(e.RoutePattern.RawText, "/api/admin/hosts/{hostId}/status", StringComparison.OrdinalIgnoreCase));

        // Cookie-based endpoints must carry ISmartInviteCsrfMetadata
        foreach (var csrfProtectedRoute in new[]
        {
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/logout"
        })
        {
            var endpoint = Assert.Single(routeEndpoints, e =>
                string.Equals((e.RoutePattern.RawText ?? string.Empty).TrimEnd('/'), csrfProtectedRoute, StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(endpoint.Metadata.GetMetadata<ISmartInviteCsrfMetadata>());
        }

        // Bearer endpoints must NOT carry ISmartInviteCsrfMetadata and must require authorization
        foreach (var (bearerRoute, expectedPolicy) in new[]
        {
            ("/api/auth/me", AuthorizationPolicies.Authenticated),
            ("/api/auth/logout-all", AuthorizationPolicies.Authenticated),
            ("/api/admin/hosts", AuthorizationPolicies.AdminOnly),
            ("/api/admin/hosts/{hostId}/lock", AuthorizationPolicies.AdminOnly),
            ("/api/admin/hosts/{hostId}/unlock", AuthorizationPolicies.AdminOnly)
        })
        {
            var endpoint = Assert.Single(routeEndpoints, e =>
                string.Equals((e.RoutePattern.RawText ?? string.Empty).TrimEnd('/'), bearerRoute, StringComparison.OrdinalIgnoreCase));
            Assert.Null(endpoint.Metadata.GetMetadata<ISmartInviteCsrfMetadata>());

            var authorizeMetadata = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>();
            Assert.Contains(authorizeMetadata, m => m.Policy == expectedPolicy);
        }
    }

    [Fact]
    public async Task MinimalWirePayloads_LoginRefreshCreateHostLockAndAuthMe_NeverExposeRefreshTokenOrLegacyCookies()
    {
        await using var stubFactory = CreateRealJwtNonDbFactory();
        using var client = new TestSessionClient(stubFactory, "198.51.100.73");
        var (csrf, _) = await client.FetchCsrfTokenAsync();

        // 1. Login returns JWT in JSON and sets __Host-SmartInvite.Refresh cookie (no __Host-SmartInvite.Auth cookie)
        var loginResp = await client.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new { email = "admin@example.invalid", password = $"Adm#{Guid.NewGuid():N}Aa1!" },
            csrfToken: csrf);

        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        var loginJson = await loginResp.Content.ReadAsStringAsync();
        using var loginDoc = JsonDocument.Parse(loginJson);
        var loginData = loginDoc.RootElement.GetProperty("data");
        var loginKeys = loginData.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(["accessToken", "expiresInSeconds", "tokenType", "user"], loginKeys);
        Assert.Equal("Bearer", loginData.GetProperty("tokenType").GetString());
        Assert.Equal(900, loginData.GetProperty("expiresInSeconds").GetInt32());

        Assert.True(loginResp.Headers.TryGetValues("Set-Cookie", out var loginCookies));
        var refreshCookieHeader = Assert.Single(loginCookies, c =>
            c.StartsWith($"{SecurityCookieConstants.RefreshCookieName}=", StringComparison.Ordinal));
        Assert.Contains("httponly", refreshCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", refreshCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", refreshCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/api/auth", refreshCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", refreshCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(loginCookies, c => c.StartsWith("__Host-SmartInvite.Auth=", StringComparison.OrdinalIgnoreCase));

        var capturedRawRefresh = client.Cookies[SecurityCookieConstants.RefreshCookieName];
        Assert.DoesNotContain(capturedRawRefresh, loginJson, StringComparison.Ordinal);

        client.AccessToken = loginData.GetProperty("accessToken").GetString();

        // 2. Refresh returns only accessToken, tokenType, expiresInSeconds (no refreshToken in JSON)
        var refreshResp = await client.SendAsync(HttpMethod.Post, "/api/auth/refresh", csrfToken: csrf);
        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);
        var refreshJson = await refreshResp.Content.ReadAsStringAsync();
        using var refreshDoc = JsonDocument.Parse(refreshJson);
        var refreshKeys = refreshDoc.RootElement.GetProperty("data").EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(["accessToken", "expiresInSeconds", "tokenType"], refreshKeys);
        Assert.DoesNotContain("refreshToken", refreshJson, StringComparison.OrdinalIgnoreCase);

        // 3. CreateHost & Me payloads remain strictly minimal
        var createResp = await client.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new
            {
                email = "host@gmail.com",
                displayName = "Nguyễn Văn A",
                initialPassword = $"Host#{Guid.NewGuid():N}Aa1!"
            });

        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);
        var createJson = await createResp.Content.ReadAsStringAsync();
        using var createDoc = JsonDocument.Parse(createJson);
        var hostKeys = createDoc.RootElement.GetProperty("data").EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(["createdAt", "displayName", "email", "id", "isLocked", "lastLoginAt"], hostKeys);

        var meResp = await client.SendAsync(HttpMethod.Get, "/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);
        var meJson = await meResp.Content.ReadAsStringAsync();
        using var meDoc = JsonDocument.Parse(meJson);
        var meKeys = meDoc.RootElement.GetProperty("data").EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(["displayName", "email", "id", "lastLoginAt", "roles"], meKeys);

        foreach (var forbiddenWireKey in new[]
        {
            "refreshToken",
            "signingKey",
            "status",
            "phoneNumber",
            "organizationName",
            "fullName",
            "hostProfileId",
            "passwordHash",
            "securityStamp",
            "concurrencyStamp",
            "lockoutEnd",
            "accessFailedCount",
            "emailConfirmed",
            "rowVersion"
        })
        {
            Assert.DoesNotContain($"\"{forbiddenWireKey}\"", loginJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain($"\"{forbiddenWireKey}\"", refreshJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain($"\"{forbiddenWireKey}\"", createJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain($"\"{forbiddenWireKey}\"", meJson, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task MalformedJsonPayload_WithValidCsrf_ShouldReturn400ValidationError_WithoutStackTrace()
    {
        using var client = new TestSessionClient(_factory, "198.51.100.71");
        var (csrfToken, _) = await client.FetchCsrfTokenAsync();

        var response = await client.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            csrfToken: csrfToken,
            configure: req =>
            {
                req.Content = new StringContent("{ malformed-json", Encoding.UTF8, "application/json");
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var raw = await response.Content.ReadAsStringAsync();
        var envelope = JsonSerializer.Deserialize<ErrorEnvelope>(raw, JsonOptions);
        Assert.NotNull(envelope);
        Assert.Equal(ErrorCodes.ValidationError, envelope.Error.Code);
        Assert.DoesNotContain("JsonException", raw);
    }

    private Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> CreateRealJwtNonDbFactory() =>
        _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IAccessTokenStateValidator>();
                services.AddScoped<IAccessTokenStateValidator, StubActiveTokenStateValidator>();
                services.AddScoped<IAdminHostService, StubAdminHostService>();
                services.AddScoped<IAuthSessionService, StubAuthSessionService>();
            });
        });

    private static string CreateTestJwt(
        string signingKey,
        string issuer,
        string audience,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        string role)
    {
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var claims = new[]
        {
            new Claim(JwtClaimNames.Sub, Guid.NewGuid().ToString()),
            new Claim(JwtClaimNames.Email, "user@example.invalid"),
            new Claim(JwtClaimNames.Name, "Test User"),
            new Claim(JwtClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new Claim(JwtClaimNames.Iat, issuedAtUtc.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
            new Claim(JwtClaimNames.SecurityStampHash, TokenCryptoHelper.ComputeSha256Hex("TEST-STAMP")),
            new Claim(JwtClaimNames.Role, role)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = issuer,
            Audience = audience,
            IssuedAt = issuedAtUtc.UtcDateTime,
            NotBefore = issuedAtUtc.UtcDateTime,
            Expires = expiresAtUtc.UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
                SecurityAlgorithms.HmacSha256)
        };

        return handler.CreateToken(descriptor);
    }

    private static async Task<ErrorEnvelope> ReadErrorEnvelopeAsync(HttpResponseMessage response)
    {
        var content = await response.Content.ReadAsStringAsync();
        var envelope = JsonSerializer.Deserialize<ErrorEnvelope>(content, JsonOptions);
        Assert.NotNull(envelope);
        Assert.NotNull(envelope.Error);
        return envelope;
    }

    private sealed class StubActiveTokenStateValidator : IAccessTokenStateValidator
    {
        public static readonly Guid AdminId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        public static readonly Guid HostId = Guid.Parse("22222222-2222-2222-2222-222222222222");

        public Task<bool> IsPrincipalActiveAsync(ClaimsPrincipal? principal, CancellationToken cancellationToken = default)
        {
            var sub = principal?.FindFirst(JwtClaimNames.Sub)?.Value;
            return Task.FromResult(Guid.TryParse(sub, out var id) && id != Guid.Empty);
        }
    }

    private sealed class ThrowingAuthSessionService : IAuthSessionService
    {
        public Task<Result<LoginSessionResult>> LoginAsync(LoginRequest? request, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("SimulatedFailure for production exception test.");

        public Task<Result<RefreshSessionResult>> RefreshAsync(string? rawRefreshToken, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("SimulatedFailure");

        public Task<Result<LogoutResponseDto>> LogoutAsync(string? rawRefreshToken, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("SimulatedFailure");

        public Task<Result<LogoutResponseDto>> LogoutAllAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("SimulatedFailure");

        public Task<Result<AuthenticatedUserDto>> GetCurrentUserAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("SimulatedFailure");
    }

    private sealed class StubAdminHostService : IAdminHostService
    {
        public Task<Result<HostSummaryDto>> CreateHostAsync(CreateHostRequest? request, CancellationToken cancellationToken = default)
        {
            var validated = AdminHostRequestValidator.ValidateCreateHost(request);
            if (validated.IsFailure)
            {
                return Task.FromResult(Result.Failure<HostSummaryDto>(validated.Error));
            }

            var createdAt = new DateTimeOffset(2026, 11, 1, 8, 0, 0, TimeSpan.Zero);
            return Task.FromResult(Result.Success(new HostSummaryDto(
                Guid.NewGuid(),
                validated.Value.Email,
                validated.Value.DisplayName,
                IsLocked: false,
                CreatedAt: createdAt,
                LastLoginAt: null)));
        }

        public Task<Result<HostSummaryDto>> LockHostAsync(Guid hostId, CancellationToken cancellationToken = default)
        {
            var createdAt = new DateTimeOffset(2026, 11, 1, 8, 0, 0, TimeSpan.Zero);
            return Task.FromResult(Result.Success(new HostSummaryDto(
                hostId,
                "host@gmail.com",
                "Nguyễn Văn A",
                IsLocked: true,
                CreatedAt: createdAt,
                LastLoginAt: null)));
        }

        public Task<Result<HostSummaryDto>> UnlockHostAsync(Guid hostId, CancellationToken cancellationToken = default)
        {
            var createdAt = new DateTimeOffset(2026, 11, 1, 8, 0, 0, TimeSpan.Zero);
            return Task.FromResult(Result.Success(new HostSummaryDto(
                hostId,
                "host@gmail.com",
                "Nguyễn Văn A",
                IsLocked: false,
                CreatedAt: createdAt,
                LastLoginAt: null)));
        }
    }

    private sealed class StubAuthSessionService(IAccessTokenService accessTokenService) : IAuthSessionService
    {
        public Task<Result<LoginSessionResult>> LoginAsync(LoginRequest? request, CancellationToken cancellationToken = default)
        {
            var utcNow = DateTimeOffset.UtcNow;
            var userDto = new AuthenticatedUserDto(
                StubActiveTokenStateValidator.AdminId,
                "admin@example.invalid",
                "System Admin",
                [RoleNames.Admin],
                utcNow);

            var jwt = accessTokenService.CreateAccessToken(
                new AccessTokenSubject(userDto.Id, userDto.Email, userDto.DisplayName, userDto.Roles, "ADMIN-STAMP-1"),
                utcNow);

            var rawRefresh = TokenCryptoHelper.GenerateSecureRefreshToken();

            return Task.FromResult(Result.Success(new LoginSessionResult(
                new LoginResponseDto(jwt.AccessToken, AuthTokenConstants.BearerTokenType, jwt.ExpiresInSeconds, userDto),
                rawRefresh,
                utcNow.AddDays(7))));
        }

        public Task<Result<RefreshSessionResult>> RefreshAsync(string? rawRefreshToken, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(rawRefreshToken))
            {
                return Task.FromResult(Result.Failure<RefreshSessionResult>(
                    Error.Unauthorized(ErrorCodes.InvalidRefreshToken, "Phiên làm mới không hợp lệ hoặc đã hết hạn.")));
            }

            var utcNow = DateTimeOffset.UtcNow;
            var jwt = accessTokenService.CreateAccessToken(
                new AccessTokenSubject(
                    StubActiveTokenStateValidator.AdminId,
                    "admin@example.invalid",
                    "System Admin",
                    [RoleNames.Admin],
                    "ADMIN-STAMP-1"),
                utcNow);

            var rotatedRaw = TokenCryptoHelper.GenerateSecureRefreshToken();

            return Task.FromResult(Result.Success(new RefreshSessionResult(
                new RefreshResponseDto(jwt.AccessToken, AuthTokenConstants.BearerTokenType, jwt.ExpiresInSeconds),
                rotatedRaw,
                utcNow.AddDays(7))));
        }

        public Task<Result<LogoutResponseDto>> LogoutAsync(string? rawRefreshToken, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Success(new LogoutResponseDto(SignedOut: true)));

        public Task<Result<LogoutResponseDto>> LogoutAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Success(new LogoutResponseDto(SignedOut: true)));

        public Task<Result<AuthenticatedUserDto>> GetCurrentUserAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Success(new AuthenticatedUserDto(
                StubActiveTokenStateValidator.AdminId,
                "admin@example.invalid",
                "System Admin",
                [RoleNames.Admin],
                DateTimeOffset.UtcNow)));
    }
}
