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
    public void RefreshCookieService_EnforcesHttpOnlySecureSameSiteLaxAndAuthPath_AndLegacyAuthCookieRemoved()
    {
        Assert.Equal("__Host-SmartInvite.Refresh", SecurityCookieConstants.RefreshCookieName);
        Assert.Equal("/api/auth", SecurityCookieConstants.RefreshCookiePath);
        Assert.Equal("__Host-SmartInvite.Antiforgery", SecurityCookieConstants.AntiforgeryCookieName);
        Assert.Equal("/", SecurityCookieConstants.AntiforgeryCookiePath);

        var cookieConstantValues = typeof(SecurityCookieConstants)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(f => f.GetValue(null)?.ToString() ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain("__Host-SmartInvite.Auth", cookieConstantValues, StringComparer.OrdinalIgnoreCase);

        var utcNow = new DateTimeOffset(2026, 11, 1, 9, 0, 0, TimeSpan.Zero);
        var expiresAt = utcNow.AddDays(7);

        var appendOptions = RefreshCookieService.BuildAppendOptions(utcNow, expiresAt);
        Assert.True(appendOptions.HttpOnly);
        Assert.True(appendOptions.Secure);
        Assert.Equal(SameSiteMode.Lax, appendOptions.SameSite);
        Assert.Equal("/api/auth", appendOptions.Path);
        Assert.Null(appendOptions.Domain);
        Assert.Equal(TimeSpan.FromDays(7), appendOptions.MaxAge);
        Assert.Equal(expiresAt, appendOptions.Expires);

        var deleteOptions = RefreshCookieService.BuildDeleteOptions();
        Assert.True(deleteOptions.HttpOnly);
        Assert.True(deleteOptions.Secure);
        Assert.Equal(SameSiteMode.Lax, deleteOptions.SameSite);
        Assert.Equal("/api/auth", deleteOptions.Path);
        Assert.Null(deleteOptions.Domain);
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

