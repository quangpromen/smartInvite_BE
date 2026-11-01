using System.Buffers.Text;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SmartInvite.Api.Common;
using SmartInvite.Api.Extensions;
using SmartInvite.Api.OpenApi;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Identity;
using SmartInvite.Infrastructure.Persistence;
using Xunit;

namespace SmartInvite.UnitTests.Identity;

public class JwtAndRefreshTokenUnitTests
{
    private static JwtOptions CreateValidJwtOptions(int accessTokenMinutes = 15, int refreshTokenDays = 7) =>
        new()
        {
            Issuer = "SmartInvite.Api",
            Audience = "SmartInvite.Web",
            SigningKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            AccessTokenMinutes = accessTokenMinutes,
            RefreshTokenDays = refreshTokenDays,
            ClockSkewSeconds = 30
        };

    [Fact]
    public void JwtOptionsValidator_ValidConfiguration_SucceedsAndResolvesKeyBytes()
    {
        var options = CreateValidJwtOptions();

        var validation = JwtOptionsValidator.Validate(options);
        var keyResult = JwtOptionsValidator.ValidateAndResolveSigningKey(options);

        Assert.True(validation.IsSuccess);
        Assert.True(keyResult.IsSuccess);
        Assert.True(keyResult.Value.Length >= JwtOptions.MinimumSigningKeyBytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("short-key-under-32-bytes")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void JwtOptionsValidator_MissingShortOrLowEntropySigningKey_FailsWithoutLeakingKey(string badKey)
    {
        var options = new JwtOptions
        {
            Issuer = "SmartInvite.Api",
            Audience = "SmartInvite.Web",
            SigningKey = badKey,
            AccessTokenMinutes = 15,
            RefreshTokenDays = 7,
            ClockSkewSeconds = 30
        };

        var result = JwtOptionsValidator.Validate(options);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorCodes.TokenConfigurationInvalid, result.Error.Code);

        if (!string.IsNullOrWhiteSpace(badKey))
        {
            Assert.DoesNotContain(badKey, result.Error.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void JwtOptionsValidator_Base64KeyDecodingUnder32Bytes_FailsValidation()
    {
        // 22 random bytes in Base64 is 32 ASCII chars ending with "==", which must still be rejected (< 32 decoded bytes)
        var twentyTwoByteBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(22));
        Assert.Equal(32, twentyTwoByteBase64.Length);

        var options = new JwtOptions
        {
            Issuer = "SmartInvite.Api",
            Audience = "SmartInvite.Web",
            SigningKey = twentyTwoByteBase64
        };

        var result = JwtOptionsValidator.Validate(options);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorCodes.TokenConfigurationInvalid, result.Error.Code);
        Assert.DoesNotContain(twentyTwoByteBase64, result.Error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("", "SmartInvite.Web", 15, 7, 30)]
    [InlineData("SmartInvite.Api", "", 15, 7, 30)]
    [InlineData("SmartInvite.Api", "SmartInvite.Web", 0, 7, 30)]
    [InlineData("SmartInvite.Api", "SmartInvite.Web", 61, 7, 30)]
    [InlineData("SmartInvite.Api", "SmartInvite.Web", 15, 0, 30)]
    [InlineData("SmartInvite.Api", "SmartInvite.Web", 15, 91, 30)]
    [InlineData("SmartInvite.Api", "SmartInvite.Web", 15, 7, -1)]
    [InlineData("SmartInvite.Api", "SmartInvite.Web", 15, 7, 61)]
    public void JwtOptionsValidator_InvalidBoundsOrMetadata_FailsValidation(
        string issuer,
        string audience,
        int accessMinutes,
        int refreshDays,
        int clockSkewSeconds)
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var options = new JwtOptions
        {
            Issuer = issuer,
            Audience = audience,
            SigningKey = key,
            AccessTokenMinutes = accessMinutes,
            RefreshTokenDays = refreshDays,
            ClockSkewSeconds = clockSkewSeconds
        };

        var result = JwtOptionsValidator.Validate(options);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorCodes.TokenConfigurationInvalid, result.Error.Code);
        Assert.DoesNotContain(key, result.Error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void JwtAccessTokenService_EmitsExactMinimalClaims_CorrectRoles_HashedSecurityStamp_AndNoSensitiveData()
    {
        var options = CreateValidJwtOptions(accessTokenMinutes: 15);
        var service = new JwtAccessTokenService(Options.Create(options));

        var userId = Guid.NewGuid();
        var rawSecurityStamp = $"STAMP-{Guid.NewGuid():N}";
        var issuedAt = new DateTimeOffset(2026, 11, 1, 9, 0, 0, TimeSpan.Zero);

        var subject = new AccessTokenSubject(
            UserId: userId,
            Email: "host@example.invalid",
            DisplayName: "Nguyễn Văn Host",
            Roles: [RoleNames.Host, "UNEXPECTED_ROLE"],
            SecurityStamp: rawSecurityStamp);

        var tokenResult = service.CreateAccessToken(subject, issuedAt);

        Assert.Equal(900, tokenResult.ExpiresInSeconds);
        Assert.Equal(issuedAt.AddMinutes(15), tokenResult.ExpiresAt);

        var parts = tokenResult.AccessToken.Split('.');
        Assert.Equal(3, parts.Length);

        var headerJson = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0]));
        var payloadJson = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1]));

        using var headerDoc = JsonDocument.Parse(headerJson);
        Assert.Equal("HS256", headerDoc.RootElement.GetProperty("alg").GetString());
        Assert.False(headerDoc.RootElement.TryGetProperty("kid", out _));

        using var payloadDoc = JsonDocument.Parse(payloadJson);
        var payloadRoot = payloadDoc.RootElement;

        var claimKeys = payloadRoot.EnumerateObject()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        var expectedClaimKeys = new[]
        {
            "aud",
            "email",
            "exp",
            "iat",
            "iss",
            "jti",
            "name",
            "nbf",
            "role",
            "sst",
            "sub"
        };

        Assert.Equal(expectedClaimKeys, claimKeys);
        Assert.Equal(userId.ToString(), payloadRoot.GetProperty("sub").GetString());
        Assert.Equal("host@example.invalid", payloadRoot.GetProperty("email").GetString());
        Assert.Equal("Nguyễn Văn Host", payloadRoot.GetProperty("name").GetString());
        Assert.Equal(RoleNames.Host, payloadRoot.GetProperty("role").GetString());
        Assert.Equal("SmartInvite.Api", payloadRoot.GetProperty("iss").GetString());
        Assert.Equal("SmartInvite.Web", payloadRoot.GetProperty("aud").GetString());

        var expectedSst = TokenCryptoHelper.ComputeSha256Hex(rawSecurityStamp);
        Assert.Equal(expectedSst, payloadRoot.GetProperty("sst").GetString());
        Assert.NotEqual(rawSecurityStamp, payloadRoot.GetProperty("sst").GetString());

        // Verify expiry and timestamps
        var iat = payloadRoot.GetProperty("iat").GetInt64();
        var nbf = payloadRoot.GetProperty("nbf").GetInt64();
        var exp = payloadRoot.GetProperty("exp").GetInt64();

        Assert.Equal(issuedAt.ToUnixTimeSeconds(), iat);
        Assert.Equal(issuedAt.ToUnixTimeSeconds(), nbf);
        Assert.Equal(issuedAt.AddMinutes(15).ToUnixTimeSeconds(), exp);
        Assert.Equal(900, exp - nbf);

        // Ensure zero sensitive strings or fields appear anywhere in decoded JWT
        Assert.DoesNotContain(rawSecurityStamp, headerJson, StringComparison.Ordinal);
        Assert.DoesNotContain(rawSecurityStamp, payloadJson, StringComparison.Ordinal);
        Assert.DoesNotContain(options.SigningKey, headerJson, StringComparison.Ordinal);
        Assert.DoesNotContain(options.SigningKey, payloadJson, StringComparison.Ordinal);

        foreach (var forbiddenClaim in new[]
        {
            "passwordHash",
            "securityStamp",
            "concurrencyStamp",
            "phoneNumber",
            "lockoutEnd",
            "accessFailedCount",
            "refreshToken"
        })
        {
            Assert.DoesNotContain(claimKeys, k => string.Equals(k, forbiddenClaim, StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void RefreshTokenGeneration_UsesAtLeast64RandomBytes_UrlSafeBase64Url_AndHashesWithSha256Only()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => TokenCryptoHelper.GenerateSecureRefreshToken(32));

        var generatedTokens = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 64; i++)
        {
            var rawToken = TokenCryptoHelper.GenerateSecureRefreshToken();
            Assert.True(generatedTokens.Add(rawToken));

            // URL-safe Base64Url characters only (no '+', '/', or '=')
            Assert.DoesNotContain('+', rawToken);
            Assert.DoesNotContain('/', rawToken);
            Assert.DoesNotContain('=', rawToken);

            var decodedBytes = Base64Url.DecodeFromChars(rawToken);
            Assert.Equal(64, decodedBytes.Length);

            var hashHex = TokenCryptoHelper.ComputeSha256Hex(rawToken);
            Assert.Equal(64, hashHex.Length);
            Assert.NotEqual(rawToken, hashHex);
            Assert.True(RefreshToken.IsValidSha256Hex(hashHex));
            Assert.True(TokenCryptoHelper.FixedTimeEqualsSha256Hex(hashHex, rawToken));
            Assert.False(TokenCryptoHelper.FixedTimeEqualsSha256Hex(hashHex, rawToken + "x"));
            Assert.False(TokenCryptoHelper.FixedTimeEqualsSha256Hex("not-hex", rawToken));
        }
    }

    [Fact]
    public void RefreshTokenEntity_NeverStoresRawToken_AndTransitionsAcrossActiveRotatedRevokedAndExpiredStates()
    {
        var rawToken = TokenCryptoHelper.GenerateSecureRefreshToken();
        var tokenHash = TokenCryptoHelper.ComputeSha256Hex(rawToken);
        var userId = Guid.NewGuid();
        var familyId = Guid.NewGuid();
        var createdAt = new DateTimeOffset(2026, 11, 1, 9, 0, 0, TimeSpan.Zero);
        var expiresAt = createdAt.AddDays(7);

        // Passing raw refresh token instead of SHA-256 hex hash must throw immediately
        Assert.Throws<ArgumentException>(() =>
            RefreshToken.Create(userId, rawToken, familyId, createdAt, expiresAt));

        var entityProps = typeof(RefreshToken)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToArray();

        Assert.DoesNotContain("RawToken", entityProps, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Token", entityProps, StringComparer.OrdinalIgnoreCase);

        // 1. Active state
        var activeToken = RefreshToken.Create(userId, tokenHash, familyId, createdAt, expiresAt);
        Assert.Equal(RefreshTokenState.Active, activeToken.GetState(createdAt.AddMinutes(5)));
        Assert.True(activeToken.IsActive(createdAt.AddMinutes(5)));

        // 2. Expired state
        Assert.Equal(RefreshTokenState.Expired, activeToken.GetState(expiresAt));
        Assert.False(activeToken.IsActive(expiresAt));

        // 3. Rotated state
        var replacementId = Guid.NewGuid();
        var rotatedAt = createdAt.AddHours(1);
        activeToken.MarkRotated(rotatedAt, replacementId);
        Assert.Equal(RefreshTokenState.Rotated, activeToken.GetState(rotatedAt));
        Assert.False(activeToken.IsActive(rotatedAt));
        Assert.Equal(replacementId, activeToken.ReplacedByTokenId);
        Assert.Throws<InvalidOperationException>(() => activeToken.MarkRotated(rotatedAt.AddMinutes(1), Guid.NewGuid()));

        // 4. Revoked state (including revoking a rotated token on family reuse detection)
        var revokedAt = rotatedAt.AddMinutes(10);
        activeToken.MarkRevoked(revokedAt, RefreshTokenRevokeReasons.ReuseDetected);
        Assert.Equal(RefreshTokenState.Revoked, activeToken.GetState(revokedAt));
        Assert.False(activeToken.IsActive(revokedAt));
        Assert.Equal(RefreshTokenRevokeReasons.ReuseDetected, activeToken.RevokedReason);
    }

    [Fact]
    public void RefreshCookieService_EnforcesBrowserCompatibleHostPrefixRootPath_HttpOnlySecureSameSiteLax_AndMatchingDeleteOptions()
    {
        Assert.Equal("__Host-SmartInvite.Refresh", SecurityCookieConstants.RefreshCookieName);
        Assert.StartsWith("__Host-", SecurityCookieConstants.RefreshCookieName, StringComparison.Ordinal);
        Assert.Equal("/", SecurityCookieConstants.RefreshCookiePath);
        Assert.NotEqual("/api/auth", SecurityCookieConstants.RefreshCookiePath);
        Assert.Equal("__Host-SmartInvite.Antiforgery", SecurityCookieConstants.AntiforgeryCookieName);
        Assert.Equal("/", SecurityCookieConstants.AntiforgeryCookiePath);

        var cookieConstantValues = typeof(SecurityCookieConstants)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(f => f.GetValue(null)?.ToString() ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain("__Host-SmartInvite.Auth", cookieConstantValues, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("/api/auth", cookieConstantValues, StringComparer.OrdinalIgnoreCase);

        var utcNow = new DateTimeOffset(2026, 11, 1, 9, 0, 0, TimeSpan.Zero);
        var refreshTokenDays = 7;
        var expiresAt = utcNow.AddDays(refreshTokenDays);

        var appendOptions = RefreshCookieService.BuildAppendOptions(utcNow, expiresAt);
        Assert.True(appendOptions.HttpOnly);
        Assert.True(appendOptions.Secure);
        Assert.Equal(SameSiteMode.Lax, appendOptions.SameSite);
        Assert.Equal("/", appendOptions.Path);
        Assert.Null(appendOptions.Domain);
        Assert.Equal(TimeSpan.FromDays(refreshTokenDays), appendOptions.MaxAge);
        Assert.Equal(expiresAt, appendOptions.Expires);

        var deleteOptions = RefreshCookieService.BuildDeleteOptions();
        Assert.True(deleteOptions.HttpOnly);
        Assert.True(deleteOptions.Secure);
        Assert.Equal(SameSiteMode.Lax, deleteOptions.SameSite);
        Assert.Equal(appendOptions.Path, deleteOptions.Path);
        Assert.Equal("/", deleteOptions.Path);
        Assert.Null(deleteOptions.Domain);

        // Verify actual Set-Cookie wire headers for both Append and Delete satisfy RFC 6265bis __Host- browser rules
        var rawToken = TokenCryptoHelper.GenerateSecureRefreshToken();

        var appendContext = new DefaultHttpContext();
        RefreshCookieService.AppendRefreshCookie(appendContext, rawToken, utcNow, expiresAt);
        var appendHeader = Assert.Single(appendContext.Response.Headers.SetCookie)!;
        AssertValidBrowserHostRefreshSetCookieHeader(appendHeader, expectNonEmptyValue: true);
        Assert.Contains("max-age=604800", appendHeader, StringComparison.OrdinalIgnoreCase);

        var deleteContext = new DefaultHttpContext();
        RefreshCookieService.DeleteRefreshCookie(deleteContext);
        var deleteHeader = Assert.Single(deleteContext.Response.Headers.SetCookie)!;
        AssertValidBrowserHostRefreshSetCookieHeader(deleteHeader, expectNonEmptyValue: false);
    }

    [Fact]
    public void RefreshTokenReplayClassification_BeforeAndAtGraceWindowBoundary_ReturnsConcurrentLostRace_WhenReplacementIsActiveLeaf()
    {
        var graceWindow = RefreshTokenService.DefaultConcurrentRotationGraceWindow;
        Assert.True(graceWindow > TimeSpan.Zero && graceWindow <= TimeSpan.FromSeconds(5));

        var createdAt = new DateTimeOffset(2026, 11, 1, 9, 0, 0, TimeSpan.Zero);
        var rotatedAt = createdAt.AddMinutes(15);
        var tokenHash = TokenCryptoHelper.ComputeSha256Hex(TokenCryptoHelper.GenerateSecureRefreshToken());

        var rotatedToken = RefreshToken.Create(
            userId: Guid.NewGuid(),
            tokenHash: tokenHash,
            familyId: Guid.NewGuid(),
            createdAt: createdAt,
            expiresAt: createdAt.AddDays(7));
        rotatedToken.MarkRotated(rotatedAt, Guid.NewGuid());

        // 1. Thread timestamp captured slightly before winner persisted RotatedAt (-50ms)
        Assert.Equal(
            RotatedTokenReplayDisposition.ConcurrentLostRace,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt.AddMilliseconds(-50),
                graceWindow: graceWindow));

        // 2. Exact rotation timestamp (+0ms)
        Assert.Equal(
            RotatedTokenReplayDisposition.ConcurrentLostRace,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt,
                graceWindow: graceWindow));

        // 3. Inside grace window (1ms before boundary)
        Assert.Equal(
            RotatedTokenReplayDisposition.ConcurrentLostRace,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt + graceWindow - TimeSpan.FromMilliseconds(1),
                graceWindow: graceWindow));

        // 4. Exact upper boundary of grace window
        Assert.Equal(
            RotatedTokenReplayDisposition.ConcurrentLostRace,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt + graceWindow,
                graceWindow: graceWindow));
    }

    [Fact]
    public void RefreshTokenReplayClassification_AfterGraceWindowBoundary_OrWhenRevokedOrReplacementNotActiveLeaf_ReturnsReuseDetected()
    {
        var graceWindow = RefreshTokenService.DefaultConcurrentRotationGraceWindow;
        var createdAt = new DateTimeOffset(2026, 11, 1, 9, 0, 0, TimeSpan.Zero);
        var rotatedAt = createdAt.AddMinutes(15);
        var tokenHash = TokenCryptoHelper.ComputeSha256Hex(TokenCryptoHelper.GenerateSecureRefreshToken());

        var rotatedToken = RefreshToken.Create(
            userId: Guid.NewGuid(),
            tokenHash: tokenHash,
            familyId: Guid.NewGuid(),
            createdAt: createdAt,
            expiresAt: createdAt.AddDays(7));
        rotatedToken.MarkRotated(rotatedAt, Guid.NewGuid());

        // 1. 1 tick after grace window upper boundary -> ReuseDetected
        Assert.Equal(
            RotatedTokenReplayDisposition.ReuseDetected,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt + graceWindow + TimeSpan.FromTicks(1),
                graceWindow: graceWindow));

        // 2. 1ms after grace window upper boundary -> ReuseDetected
        Assert.Equal(
            RotatedTokenReplayDisposition.ReuseDetected,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt + graceWindow + TimeSpan.FromMilliseconds(1),
                graceWindow: graceWindow));

        // 3. Within grace window, but replacement token B was ALREADY rotated to C (or revoked) -> ReuseDetected
        Assert.Equal(
            RotatedTokenReplayDisposition.ReuseDetected,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: false,
                utcNow: rotatedAt.AddMilliseconds(100),
                graceWindow: graceWindow));

        // 4. Within grace window, but token A itself was explicitly revoked -> ReuseDetected
        rotatedToken.MarkRevoked(rotatedAt.AddMilliseconds(50), RefreshTokenRevokeReasons.Logout);
        Assert.Equal(
            RotatedTokenReplayDisposition.ReuseDetected,
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt.AddMilliseconds(100),
                graceWindow: graceWindow));

        // 5. Out-of-bounds graceWindow configuration is rejected
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt,
                graceWindow: TimeSpan.FromSeconds(-1)));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            RefreshTokenService.ClassifyNonActiveTokenReplay(
                rotatedToken,
                replacementIsActiveLeaf: true,
                utcNow: rotatedAt,
                graceWindow: TimeSpan.FromSeconds(31)));
    }

    private static void AssertValidBrowserHostRefreshSetCookieHeader(string rawSetCookie, bool expectNonEmptyValue)
    {
        var segments = rawSetCookie.Split(';', StringSplitOptions.TrimEntries);
        Assert.NotEmpty(segments);

        var nameValue = segments[0];
        var eqIndex = nameValue.IndexOf('=');
        Assert.True(eqIndex > 0);

        var cookieName = nameValue[..eqIndex];
        var cookieValue = nameValue[(eqIndex + 1)..];

        Assert.Equal(SecurityCookieConstants.RefreshCookieName, cookieName);
        if (expectNonEmptyValue)
        {
            Assert.False(string.IsNullOrEmpty(cookieValue));
        }
        else
        {
            Assert.Equal(string.Empty, cookieValue);
        }

        var attributes = segments.Skip(1).ToArray();
        Assert.Contains(attributes, a => a.Equals("path=/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(attributes, a => a.StartsWith("path=/api", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(attributes, a => a.Equals("httponly", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(attributes, a => a.Equals("secure", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(attributes, a => a.Equals("samesite=lax", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(attributes, a => a.StartsWith("domain=", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CsrfMetadata_AppliesStrictlyToMarkedCookieEndpoints_AndSkipsBearerEndpoints()
    {
        var cookieEndpoint = new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(new RequireSmartInviteCsrfMetadata()),
            "POST /api/auth/refresh");

        var bearerPostEndpoint = new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(),
            "POST /api/admin/hosts");

        Assert.True(CsrfProtectionMiddleware.EndpointRequiresCsrf(cookieEndpoint));
        Assert.True(CsrfHeaderOperationFilter.RequiresCsrfHeader(cookieEndpoint.Metadata));

        Assert.False(CsrfProtectionMiddleware.EndpointRequiresCsrf(bearerPostEndpoint));
        Assert.False(CsrfHeaderOperationFilter.RequiresCsrfHeader(bearerPostEndpoint.Metadata));
        Assert.False(CsrfProtectionMiddleware.EndpointRequiresCsrf(null));
    }
}

