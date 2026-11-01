using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SmartInvite.Api.Common;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Identity;
using SmartInvite.Infrastructure.Persistence;
using SmartInvite.IntegrationTests.Common;
using Xunit;

namespace SmartInvite.IntegrationTests.SqlServer;

[Trait("Category", "SqlServerIntegration")]
public sealed class SqlServerIdentityIntegrationTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly SemaphoreSlim MigrationGate = new(1, 1);
    private static bool _migrationInitialized;

    private string? _connectionString;
    private string _adminEmail = string.Empty;
    private string _adminRuntimeSecret = string.Empty;
    private int _ipOctetCounter = 100;

    public async Task InitializeAsync()
    {
        _connectionString = Environment.GetEnvironmentVariable(SqlServerFactAttribute.ConnectionStringEnvVar);
        if (string.IsNullOrWhiteSpace(_connectionString))
        {
            return;
        }

        var safetyResult = SqlServerConnectionSafetyGuard.ValidateTestDatabaseConnection(_connectionString);
        if (safetyResult.IsFailure)
        {
            throw new InvalidOperationException(safetyResult.Error.Message);
        }

        _adminEmail = $"admin-{Guid.NewGuid():N}@example.invalid";
        _adminRuntimeSecret = $"Adm#{Guid.NewGuid():N}Zz9!";

        await MigrationGate.WaitAsync();
        try
        {
            if (!_migrationInitialized)
            {
                var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                    .UseSqlServer(_connectionString)
                    .Options;

                await using var dbContext = new ApplicationDbContext(options);
                await dbContext.Database.MigrateAsync();
                _migrationInitialized = true;
            }
        }
        finally
        {
            MigrationGate.Release();
        }
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [SqlServerFact]
    public async Task Migration_InitialIdentityAndAddRefreshTokens_ApplyCleanlyOnTestSqlServerDatabase()
    {
        await using var factory = CreateSqlServerFactory();
        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var pending = await dbContext.Database.GetPendingMigrationsAsync();
        var applied = (await dbContext.Database.GetAppliedMigrationsAsync()).ToArray();

        Assert.Empty(pending);
        Assert.Contains(applied, m => m.EndsWith("_InitialIdentity", StringComparison.Ordinal));
        Assert.Contains(applied, m => m.EndsWith("_AddRefreshTokens", StringComparison.Ordinal));
        Assert.True(await dbContext.Database.CanConnectAsync());
    }

    [SqlServerFact]
    public async Task DatabaseSchema_HasRefreshTokensTableAndMinimalAspNetUsers_WithoutBe2OrLegacyTables()
    {
        await using var factory = CreateSqlServerFactory();
        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var tables = await dbContext.Database
            .SqlQueryRaw<string>("SELECT TABLE_NAME AS [Value] FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
            .ToListAsync();

        Assert.Contains("AspNetUsers", tables, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("RefreshTokens", tables, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("HostProfiles", tables, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Events", tables, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Cards", tables, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Guests", tables, StringComparer.OrdinalIgnoreCase);

        var userColumns = await dbContext.Database
            .SqlQueryRaw<string>("SELECT COLUMN_NAME AS [Value] FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'AspNetUsers'")
            .ToListAsync();

        Assert.Contains("DisplayName", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("CreatedAt", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("LastLoginAt", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("PhoneNumber", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("PhoneNumberConfirmed", userColumns, StringComparer.OrdinalIgnoreCase);

        Assert.DoesNotContain("Status", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("UpdatedAt", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("RowVersion", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("FullName", userColumns, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("OrganizationName", userColumns, StringComparer.OrdinalIgnoreCase);

        var refreshColumns = await dbContext.Database
            .SqlQueryRaw<string>("SELECT COLUMN_NAME AS [Value] FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'RefreshTokens'")
            .ToListAsync();

        Assert.Contains("Id", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("UserId", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("TokenHash", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("FamilyId", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("CreatedAt", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("ExpiresAt", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("RotatedAt", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("RevokedAt", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("ReplacedByTokenId", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("RevokedReason", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("RawToken", refreshColumns, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Token", refreshColumns, StringComparer.OrdinalIgnoreCase);

        var customDeclaredUserProperties = typeof(ApplicationUser)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["CreatedAt", "DisplayName", "LastLoginAt"], customDeclaredUserProperties);
    }

    [SqlServerFact]
    public async Task BootstrapAdmin_ExecutesIdempotently_WithoutResettingPasswordOrDuplicatingUser()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        _ = factory.Services;

        Guid firstUserId;
        string? firstHash;

        await using (var scope1 = factory.Services.CreateAsyncScope())
        {
            var userManager = scope1.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var admin = await userManager.FindByEmailAsync(_adminEmail);
            Assert.NotNull(admin);
            firstUserId = admin.Id;
            firstHash = admin.PasswordHash;

            var bootstrapService = scope1.ServiceProvider.GetRequiredService<AdminBootstrapService>();
            await bootstrapService.ExecuteAsync();
        }

        await using (var scope2 = factory.Services.CreateAsyncScope())
        {
            var dbContext = scope2.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var matchingUsers = await dbContext.Users
                .Where(u => u.Email == _adminEmail)
                .ToListAsync();

            var singleAdmin = Assert.Single(matchingUsers);
            Assert.Equal(firstUserId, singleAdmin.Id);
            Assert.Equal(firstHash, singleAdmin.PasswordHash);
            Assert.Null(singleAdmin.PhoneNumber);
            Assert.False(singleAdmin.PhoneNumberConfirmed);
        }
    }

    [SqlServerFact]
    public async Task AdminCreateHost_PersistsSimplifiedUserWithHostRoleOnly_AndLeavesIdentityPhoneNull()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        var (hostSummary, _) = await CreateHostAsAdminAsync(factory);

        Assert.False(hostSummary.IsLocked);
        Assert.Null(hostSummary.LastLoginAt);

        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var createdUser = await userManager.FindByIdAsync(hostSummary.Id.ToString());
        Assert.NotNull(createdUser);
        Assert.Equal("Host Tốt Nghiệp", createdUser.DisplayName);
        Assert.False(createdUser.EmailConfirmed);
        Assert.Null(createdUser.PhoneNumber);
        Assert.False(createdUser.PhoneNumberConfirmed);
        Assert.True(createdUser.LockoutEnabled);

        var roles = await userManager.GetRolesAsync(createdUser);
        Assert.Equal([RoleNames.Host], roles);
    }

    [SqlServerFact]
    public async Task AdminCreateHost_DuplicateNormalizedEmail_Returns409_AndRollbackWorksWhenRoleAssignmentFails()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        var (existingHost, _) = await CreateHostAsAdminAsync(factory);

        using var adminClient = await LoginSessionAsync(factory, _adminEmail, _adminRuntimeSecret);

        var duplicateResp = await adminClient.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new CreateHostRequest(
                existingHost.Email.ToUpperInvariant(),
                "Duplicate Display",
                $"Host#{Guid.NewGuid():N}Aa1!"));

        Assert.Equal(HttpStatusCode.Conflict, duplicateResp.StatusCode);
        var err = await duplicateResp.Content.ReadFromJsonAsync<ErrorEnvelope>(JsonOptions);
        Assert.Equal(ErrorCodes.EmailAlreadyExists, err!.Error.Code);

        await using var rollbackFactory = CreateSqlServerFactory(
            enableBootstrap: true,
            configureTestServices: services =>
            {
                services.AddSingleton<IAdminHostExecutionSeam, FailingAddRoleExecutionSeam>();
            });

        using var rollbackAdminClient = await LoginSessionAsync(rollbackFactory, _adminEmail, _adminRuntimeSecret);
        var rollbackEmail = $"rollback-{Guid.NewGuid():N}@example.invalid";

        var rollbackResp = await rollbackAdminClient.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new CreateHostRequest(
                rollbackEmail,
                "Rollback Host",
                $"Host#{Guid.NewGuid():N}Aa1!"));

        Assert.Equal(HttpStatusCode.InternalServerError, rollbackResp.StatusCode);

        await using var verifyScope = rollbackFactory.Services.CreateAsyncScope();
        var dbContext = verifyScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var orphanUser = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == rollbackEmail);
        Assert.Null(orphanUser);
    }

    [SqlServerFact]
    public async Task Login_IssuesJwtBearerAndStrictRefreshCookie_StoresOnlySha256TokenHash_AndUpdatesLastLoginAt()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        using var adminClient = new TestSessionClient(factory, NextClientIp());

        var (csrf, _) = await adminClient.FetchCsrfTokenAsync();
        var loginResp = await adminClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest(_adminEmail, _adminRuntimeSecret),
            csrfToken: csrf);

        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        var rawLoginBody = await loginResp.Content.ReadAsStringAsync();

        var envelope = JsonSerializer.Deserialize<ApiEnvelope<LoginResponseDto>>(rawLoginBody, JsonOptions);
        Assert.NotNull(envelope);
        Assert.False(string.IsNullOrWhiteSpace(envelope.Data.AccessToken));
        Assert.Equal("Bearer", envelope.Data.TokenType);
        Assert.Equal(900, envelope.Data.ExpiresInSeconds);
        Assert.Equal("BE1 Test Admin", envelope.Data.User.DisplayName);
        Assert.NotNull(envelope.Data.User.LastLoginAt);

        // Verify Refresh Cookie attributes and absence of legacy __Host-SmartInvite.Auth cookie
        Assert.True(adminClient.Cookies.TryGetValue(SecurityCookieConstants.RefreshCookieName, out var rawRefreshToken));
        Assert.False(string.IsNullOrWhiteSpace(rawRefreshToken));
        Assert.False(adminClient.Cookies.ContainsKey("__Host-SmartInvite.Auth"));
        Assert.DoesNotContain(rawRefreshToken, rawLoginBody, StringComparison.Ordinal);

        Assert.True(loginResp.Headers.TryGetValues("Set-Cookie", out var setCookies));
        var refreshSetCookie = Assert.Single(setCookies, c =>
            c.StartsWith($"{SecurityCookieConstants.RefreshCookieName}=", StringComparison.Ordinal));
        Assert.Contains("httponly", refreshSetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", refreshSetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", refreshSetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/api/auth", refreshSetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", refreshSetCookie, StringComparison.OrdinalIgnoreCase);

        // Verify SQL Server stores ONLY SHA-256 hash and NEVER raw refresh token
        var expectedHash = TokenCryptoHelper.ComputeSha256Hex(rawRefreshToken);

        await using var scope = factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var adminUser = await userManager.FindByEmailAsync(_adminEmail);
        Assert.NotNull(adminUser?.LastLoginAt);

        var rawMatchInDb = await dbContext.RefreshTokens
            .AnyAsync(t => t.TokenHash == rawRefreshToken);
        Assert.False(rawMatchInDb);

        var storedToken = await dbContext.RefreshTokens
            .SingleOrDefaultAsync(t => t.TokenHash == expectedHash);
        Assert.NotNull(storedToken);
        Assert.Equal(adminUser!.Id, storedToken.UserId);
        Assert.Null(storedToken.RotatedAt);
        Assert.Null(storedToken.RevokedAt);
        Assert.True(storedToken.ExpiresAt > storedToken.CreatedAt);
    }

    [SqlServerFact]
    public async Task RefreshRotation_RotatesToken_RejectsSecondUse_AndRevokesEntireFamilyOnReuseDetection()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        var (hostSummary, hostSecret) = await CreateHostAsAdminAsync(factory);

        using var hostClient = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        var firstRawRefresh = hostClient.Cookies[SecurityCookieConstants.RefreshCookieName];
        var firstHash = TokenCryptoHelper.ComputeSha256Hex(firstRawRefresh);

        var (csrf, _) = await hostClient.FetchCsrfTokenAsync();

        // 1. Valid refresh rotates RT1 -> RT2 in the same FamilyId
        var refreshResp = await hostClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/refresh",
            csrfToken: csrf);

        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);
        var refreshEnvelope = await refreshResp.Content.ReadFromJsonAsync<ApiEnvelope<RefreshResponseDto>>(JsonOptions);
        Assert.NotNull(refreshEnvelope);
        Assert.False(string.IsNullOrWhiteSpace(refreshEnvelope.Data.AccessToken));
        Assert.Equal("Bearer", refreshEnvelope.Data.TokenType);
        Assert.Equal(900, refreshEnvelope.Data.ExpiresInSeconds);

        var secondRawRefresh = hostClient.Cookies[SecurityCookieConstants.RefreshCookieName];
        Assert.NotEqual(firstRawRefresh, secondRawRefresh);
        var secondHash = TokenCryptoHelper.ComputeSha256Hex(secondRawRefresh);

        await using (var checkScope = factory.Services.CreateAsyncScope())
        {
            var db = checkScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var rt1 = await db.RefreshTokens.SingleAsync(t => t.TokenHash == firstHash);
            var rt2 = await db.RefreshTokens.SingleAsync(t => t.TokenHash == secondHash);

            Assert.NotNull(rt1.RotatedAt);
            Assert.Equal(rt2.Id, rt1.ReplacedByTokenId);
            Assert.Equal(rt1.FamilyId, rt2.FamilyId);
            Assert.Null(rt2.RotatedAt);
            Assert.Null(rt2.RevokedAt);
        }

        // 2. Replaying rotated RT1 fails with generic 401 INVALID_REFRESH_TOKEN AND revokes entire Family (including active RT2!)
        using var attackerClient = new TestSessionClient(factory, NextClientIp());
        var (attackerCsrf, _) = await attackerClient.FetchCsrfTokenAsync();
        attackerClient.SetCookie(SecurityCookieConstants.RefreshCookieName, firstRawRefresh, SecurityCookieConstants.RefreshCookiePath);

        var replayResp = await attackerClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/refresh",
            csrfToken: attackerCsrf);

        Assert.Equal(HttpStatusCode.Unauthorized, replayResp.StatusCode);
        var replayErr = await replayResp.Content.ReadFromJsonAsync<ErrorEnvelope>(JsonOptions);
        Assert.Equal(ErrorCodes.InvalidRefreshToken, replayErr!.Error.Code);

        // Compare public error message against an unknown refresh token to verify attacker cannot distinguish states
        using var unknownTokenClient = new TestSessionClient(factory, NextClientIp());
        var (unknownCsrf, _) = await unknownTokenClient.FetchCsrfTokenAsync();
        unknownTokenClient.SetCookie(
            SecurityCookieConstants.RefreshCookieName,
            TokenCryptoHelper.GenerateSecureRefreshToken(),
            SecurityCookieConstants.RefreshCookiePath);
        var unknownResp = await unknownTokenClient.SendAsync(HttpMethod.Post, "/api/auth/refresh", csrfToken: unknownCsrf);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownResp.StatusCode);
        var unknownErr = await unknownResp.Content.ReadFromJsonAsync<ErrorEnvelope>(JsonOptions);
        Assert.Equal(replayErr.Error.Code, unknownErr!.Error.Code);
        Assert.Equal(replayErr.Error.Message, unknownErr.Error.Message);

        // 3. Legitimate client's RT2 is now ALSO rejected because reuse detection revoked the entire family!
        var postReuseRefreshResp = await hostClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/refresh",
            csrfToken: csrf);
        Assert.Equal(HttpStatusCode.Unauthorized, postReuseRefreshResp.StatusCode);

        await using (var familyScope = factory.Services.CreateAsyncScope())
        {
            var db = familyScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var rt2Reloaded = await db.RefreshTokens.SingleAsync(t => t.TokenHash == secondHash);
            Assert.NotNull(rt2Reloaded.RevokedAt);
            Assert.Equal(RefreshTokenRevokeReasons.ReuseDetected, rt2Reloaded.RevokedReason);
        }
    }

    [SqlServerFact]
    public async Task ConcurrentRefresh_WithSameRefreshToken_AllowsStrictlyOneSuccessAndRejectsCompetingRequest()
    {
        var barrier = new ConcurrentRefreshBarrierSeam();
        await using var factory = CreateSqlServerFactory(
            enableBootstrap: true,
            configureTestServices: services =>
            {
                services.AddSingleton<IRefreshTokenExecutionSeam>(barrier);
            });

        var (hostSummary, hostSecret) = await CreateHostAsAdminAsync(factory);
        using var initialClient = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        var sharedRefreshToken = initialClient.Cookies[SecurityCookieConstants.RefreshCookieName];

        using var concurrentClientA = new TestSessionClient(factory, NextClientIp());
        using var concurrentClientB = new TestSessionClient(factory, NextClientIp());

        var (csrfA, _) = await concurrentClientA.FetchCsrfTokenAsync();
        var (csrfB, _) = await concurrentClientB.FetchCsrfTokenAsync();

        concurrentClientA.SetCookie(SecurityCookieConstants.RefreshCookieName, sharedRefreshToken, SecurityCookieConstants.RefreshCookiePath);
        concurrentClientB.SetCookie(SecurityCookieConstants.RefreshCookieName, sharedRefreshToken, SecurityCookieConstants.RefreshCookiePath);

        barrier.ArmForTwoConcurrentCallers();

        var taskA = concurrentClientA.SendAsync(HttpMethod.Post, "/api/auth/refresh", csrfToken: csrfA);
        var taskB = concurrentClientB.SendAsync(HttpMethod.Post, "/api/auth/refresh", csrfToken: csrfB);

        var responses = await Task.WhenAll(taskA, taskB);

        var successCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        var unauthorizedCount = responses.Count(r => r.StatusCode == HttpStatusCode.Unauthorized);

        Assert.Equal(1, successCount);
        Assert.Equal(1, unauthorizedCount);
    }

    [SqlServerFact]
    public async Task Logout_RevokesCurrentRefreshToken_AndLogoutAll_RevokesAllUserTokensAndInvalidatesExistingAccessTokens()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        var (hostSummary, hostSecret) = await CreateHostAsAdminAsync(factory);

        // Session 1: test single-session Logout (without Bearer header — idempotent cookie revocation)
        using var session1 = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        var session1Refresh = session1.Cookies[SecurityCookieConstants.RefreshCookieName];
        var session1Hash = TokenCryptoHelper.ComputeSha256Hex(session1Refresh);
        session1.AccessToken = null; // prove logout works even when access token is expired/absent

        var (csrf1, _) = await session1.FetchCsrfTokenAsync();
        var logoutResp = await session1.SendAsync(HttpMethod.Post, "/api/auth/logout", csrfToken: csrf1);
        Assert.Equal(HttpStatusCode.OK, logoutResp.StatusCode);
        Assert.False(session1.Cookies.ContainsKey(SecurityCookieConstants.RefreshCookieName));

        await using (var scope1 = factory.Services.CreateAsyncScope())
        {
            var db = scope1.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var revoked1 = await db.RefreshTokens.SingleAsync(t => t.TokenHash == session1Hash);
            Assert.NotNull(revoked1.RevokedAt);
            Assert.Equal(RefreshTokenRevokeReasons.Logout, revoked1.RevokedReason);
        }

        // Session 2 & Session 3: two independent devices logged in concurrently; Logout-All revokes BOTH and kills existing JWTs
        using var deviceA = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        using var deviceB = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);

        var deviceAJwt = deviceA.AccessToken!;
        var deviceBJwt = deviceB.AccessToken!;
        var deviceBRefresh = deviceB.Cookies[SecurityCookieConstants.RefreshCookieName];

        var logoutAllResp = await deviceA.SendAsync(HttpMethod.Post, "/api/auth/logout-all");
        Assert.Equal(HttpStatusCode.OK, logoutAllResp.StatusCode);
        Assert.False(deviceA.Cookies.ContainsKey(SecurityCookieConstants.RefreshCookieName));

        // Existing JWTs on BOTH devices are immediately invalid (401)
        var deviceAMe = await deviceA.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: deviceAJwt);
        var deviceBMe = await deviceB.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: deviceBJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, deviceAMe.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, deviceBMe.StatusCode);

        // Device B's refresh token is ALSO revoked (401)
        var (csrfB, _) = await deviceB.FetchCsrfTokenAsync();
        deviceB.SetCookie(SecurityCookieConstants.RefreshCookieName, deviceBRefresh, SecurityCookieConstants.RefreshCookiePath);
        deviceB.AccessToken = null;
        var deviceBRefreshResp = await deviceB.SendAsync(HttpMethod.Post, "/api/auth/refresh", csrfToken: csrfB);
        Assert.Equal(HttpStatusCode.Unauthorized, deviceBRefreshResp.StatusCode);

        // Password was NOT reset — user can log in again with original password
        using var reloginClient = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        var reloginMe = await reloginClient.SendAsync(HttpMethod.Get, "/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, reloginMe.StatusCode);
    }

    [SqlServerFact]
    public async Task AccessTokenValidation_RejectsWrongSignature_WrongIssuerOrAudience_AndExpiredToken()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        var (hostSummary, _) = await CreateHostAsAdminAsync(factory);

        string securityStamp;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByIdAsync(hostSummary.Id.ToString());
            securityStamp = user!.SecurityStamp!;
        }

        using var client = new TestSessionClient(factory, NextClientIp());
        var now = DateTimeOffset.UtcNow;

        var wrongSigJwt = MintCustomJwt(
            hostSummary.Id,
            hostSummary.Email,
            securityStamp,
            signingKey: Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            issuer: "SmartInvite.Api",
            audience: "SmartInvite.Web",
            issuedAt: now,
            expiresAt: now.AddMinutes(15));

        var wrongIssuerJwt = MintCustomJwt(
            hostSummary.Id,
            hostSummary.Email,
            securityStamp,
            signingKey: CustomWebApplicationFactory.TestJwtSigningKey,
            issuer: "Invalid.Issuer",
            audience: "SmartInvite.Web",
            issuedAt: now,
            expiresAt: now.AddMinutes(15));

        var wrongAudienceJwt = MintCustomJwt(
            hostSummary.Id,
            hostSummary.Email,
            securityStamp,
            signingKey: CustomWebApplicationFactory.TestJwtSigningKey,
            issuer: "SmartInvite.Api",
            audience: "Invalid.Audience",
            issuedAt: now,
            expiresAt: now.AddMinutes(15));

        var expiredJwt = MintCustomJwt(
            hostSummary.Id,
            hostSummary.Email,
            securityStamp,
            signingKey: CustomWebApplicationFactory.TestJwtSigningKey,
            issuer: "SmartInvite.Api",
            audience: "SmartInvite.Web",
            issuedAt: now.AddMinutes(-20),
            expiresAt: now.AddMinutes(-5));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: wrongSigJwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: wrongIssuerJwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: wrongAudienceJwt)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: expiredJwt)).StatusCode);
    }

    [SqlServerFact]
    public async Task AdminLockAndUnlockHost_ImmediatelyInvalidatesExistingJwt_AndUnlockDoesNotRestoreOldJwt()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        var (hostSummary, hostSecret) = await CreateHostAsAdminAsync(factory);

        using var hostClient = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        var preLockJwt = hostClient.AccessToken!;
        var preLockRefresh = hostClient.Cookies[SecurityCookieConstants.RefreshCookieName];

        var beforeLockMe = await hostClient.SendAsync(HttpMethod.Get, "/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, beforeLockMe.StatusCode);

        // 1. Admin locks Host -> existing JWT fails immediately on very next request, and refresh token is revoked
        var lockedSummary = await LockHostAsAdminAsync(factory, hostSummary.Id);
        Assert.True(lockedSummary.IsLocked);

        var afterLockMe = await hostClient.SendAsync(HttpMethod.Get, "/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, afterLockMe.StatusCode);

        hostClient.AccessToken = null;
        var (hostCsrf, _) = await hostClient.FetchCsrfTokenAsync();
        hostClient.SetCookie(SecurityCookieConstants.RefreshCookieName, preLockRefresh, SecurityCookieConstants.RefreshCookiePath);
        var afterLockRefresh = await hostClient.SendAsync(HttpMethod.Post, "/api/auth/refresh", csrfToken: hostCsrf);
        Assert.Equal(HttpStatusCode.Unauthorized, afterLockRefresh.StatusCode);

        // New login during lock fails with generic INVALID_CREDENTIALS
        using var blockedLoginClient = new TestSessionClient(factory, NextClientIp());
        var (blockedCsrf, _) = await blockedLoginClient.FetchCsrfTokenAsync();
        var blockedLoginResp = await blockedLoginClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest(hostSummary.Email, hostSecret),
            csrfToken: blockedCsrf);
        Assert.Equal(HttpStatusCode.Unauthorized, blockedLoginResp.StatusCode);
        Assert.Equal(ErrorCodes.InvalidCredentials, (await blockedLoginResp.Content.ReadFromJsonAsync<ErrorEnvelope>(JsonOptions))!.Error.Code);

        // 2. Admin unlocks Host -> old pre-lock JWT STILL fails with 401 (does NOT resurrect!)
        var (unlockedSummary, unlockHttpResp) = await UnlockHostAsAdminWithResponseAsync(factory, hostSummary.Id);
        Assert.False(unlockedSummary.IsLocked);
        Assert.False(unlockHttpResp.Headers.Contains("Set-Cookie"));

        var staleJwtAfterUnlock = await hostClient.SendAsync(HttpMethod.Get, "/api/auth/me", bearerToken: preLockJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, staleJwtAfterUnlock.StatusCode);

        // Fresh login with original password works cleanly
        using var reloginClient = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        var reloginMe = await reloginClient.SendAsync(HttpMethod.Get, "/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, reloginMe.StatusCode);
    }

    [SqlServerFact]
    public async Task Login_WrongCredentials_TemporaryLockout_RolePolicies_SelfAdminGuard_AndConcurrencyConflict_WorkAsExpected()
    {
        await using var factory = CreateSqlServerFactory(enableBootstrap: true);
        var (hostSummary, hostSecret) = await CreateHostAsAdminAsync(factory);

        // 1. Generic error for wrong password vs unknown email
        using var anonClient = new TestSessionClient(factory, NextClientIp());
        var (csrf, _) = await anonClient.FetchCsrfTokenAsync();

        var wrongSecretResp = await anonClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest(_adminEmail, $"Wrong#{Guid.NewGuid():N}Aa1!"),
            csrfToken: csrf);
        var unknownEmailResp = await anonClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest($"nonexistent-{Guid.NewGuid():N}@example.invalid", $"Wrong#{Guid.NewGuid():N}Aa1!"),
            csrfToken: csrf);

        Assert.Equal(HttpStatusCode.Unauthorized, wrongSecretResp.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownEmailResp.StatusCode);

        // 2. Role enforcement: HOST Bearer token cannot call Admin APIs (403) while HostOnly succeeds (200)
        using var hostSession = await LoginSessionAsync(factory, hostSummary.Email, hostSecret);
        Assert.Equal(HttpStatusCode.Forbidden, (await hostSession.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new CreateHostRequest($"b-{Guid.NewGuid():N}@example.invalid", "Blocked", $"Host#{Guid.NewGuid():N}Aa1!"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await hostSession.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{hostSummary.Id}/lock")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await hostSession.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{hostSummary.Id}/unlock")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await hostSession.SendAsync(HttpMethod.Get, "/internal/test-host-only")).StatusCode);

        // 3. Temporary lockout after 5 failed attempts on a second Host
        var (lockoutHost, lockoutHostSecret) = await CreateHostAsAdminAsync(factory);
        using var ip1 = new TestSessionClient(factory, NextClientIp());
        using var ip2 = new TestSessionClient(factory, NextClientIp());
        var (csrfIp1, _) = await ip1.FetchCsrfTokenAsync();
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await ip1.SendAsync(
                HttpMethod.Post,
                "/api/auth/login",
                new LoginRequest(lockoutHost.Email, $"Wrong#{i}_{Guid.NewGuid():N}Aa1!"),
                csrfToken: csrfIp1)).StatusCode);
        }

        var (csrfIp2, _) = await ip2.FetchCsrfTokenAsync();
        for (var i = 0; i < 2; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await ip2.SendAsync(
                HttpMethod.Post,
                "/api/auth/login",
                new LoginRequest(lockoutHost.Email, $"Wrong#{i + 3}_{Guid.NewGuid():N}Aa1!"),
                csrfToken: csrfIp2)).StatusCode);
        }

        var lockedOutValidAttempt = await ip2.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest(lockoutHost.Email, lockoutHostSecret),
            csrfToken: csrfIp2);
        Assert.Equal(HttpStatusCode.Unauthorized, lockedOutValidAttempt.StatusCode);

        // 4. Unknown Host ID returns 404
        using var adminSession = await LoginSessionAsync(factory, _adminEmail, _adminRuntimeSecret);
        Assert.Equal(HttpStatusCode.NotFound, (await adminSession.SendAsync(HttpMethod.Post, $"/api/admin/hosts/{Guid.NewGuid()}/lock")).StatusCode);
    }

    [SqlServerFact]
    public async Task ResponsesAndLogs_NeverLeakAccessTokenInLogs_OrRefreshTokenSigningKeyPasswordsHashesAndStamps()
    {
        var logCollector = new InMemoryLogCollectorProvider();
        await using var factory = CreateSqlServerFactory(
            enableBootstrap: true,
            configureLogging: logging => logging.AddProvider(logCollector));

        var (hostSummary, hostSecret) = await CreateHostAsAdminAsync(factory);

        using var hostClient = new TestSessionClient(factory, NextClientIp());
        var (csrfToken, csrfResp) = await hostClient.FetchCsrfTokenAsync();
        var csrfRawBody = await csrfResp.Content.ReadAsStringAsync();

        var wrongSecret = $"Wrong#{Guid.NewGuid():N}Zz9!";
        var failedLoginResp = await hostClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest(hostSummary.Email, wrongSecret),
            csrfToken: csrfToken);
        var failedBody = await failedLoginResp.Content.ReadAsStringAsync();

        var okLoginResp = await hostClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest(hostSummary.Email, hostSecret),
            csrfToken: csrfToken);
        var okBody = await okLoginResp.Content.ReadAsStringAsync();
        var loginEnvelope = JsonSerializer.Deserialize<ApiEnvelope<LoginResponseDto>>(okBody, JsonOptions)!;
        var issuedJwt = loginEnvelope.Data.AccessToken;
        var issuedRefresh = hostClient.Cookies[SecurityCookieConstants.RefreshCookieName];
        var issuedRefreshHash = TokenCryptoHelper.ComputeSha256Hex(issuedRefresh);

        var refreshResp = await hostClient.SendAsync(
            HttpMethod.Post,
            "/api/auth/refresh",
            csrfToken: csrfToken);
        var refreshBody = await refreshResp.Content.ReadAsStringAsync();
        var rotatedRefresh = hostClient.Cookies[SecurityCookieConstants.RefreshCookieName];
        var rotatedRefreshHash = TokenCryptoHelper.ComputeSha256Hex(rotatedRefresh);

        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var dbUser = await userManager.FindByIdAsync(hostSummary.Id.ToString());
        Assert.NotNull(dbUser);

        var forbiddenInResponses = new[]
        {
            CustomWebApplicationFactory.TestJwtSigningKey,
            _adminRuntimeSecret,
            hostSecret,
            wrongSecret,
            issuedRefresh,
            rotatedRefresh,
            issuedRefreshHash,
            rotatedRefreshHash,
            dbUser.PasswordHash!,
            dbUser.SecurityStamp!,
            dbUser.ConcurrencyStamp!
        };

        foreach (var secret in forbiddenInResponses)
        {
            Assert.DoesNotContain(secret, csrfRawBody, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, failedBody, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, okBody, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, refreshBody, StringComparison.Ordinal);
        }

        var forbiddenInLogs = forbiddenInResponses.Concat([issuedJwt, csrfToken]).ToArray();
        foreach (var logMessage in logCollector.Messages)
        {
            foreach (var secret in forbiddenInLogs)
            {
                Assert.DoesNotContain(secret, logMessage, StringComparison.Ordinal);
            }
        }
    }

    private WebApplicationFactory<Program> CreateSqlServerFactory(
        bool enableBootstrap = false,
        Action<IServiceCollection>? configureTestServices = null,
        Action<ILoggingBuilder>? configureLogging = null)
    {
        var baseFactory = new CustomWebApplicationFactory();

        return baseFactory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                var settings = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:SmartInviteDatabase"] = _connectionString,
                    ["BootstrapAdmin:Enabled"] = enableBootstrap ? "true" : "false",
                    ["BootstrapAdmin:Email"] = enableBootstrap ? _adminEmail : string.Empty,
                    ["BootstrapAdmin:Password"] = enableBootstrap ? _adminRuntimeSecret : string.Empty,
                    ["BootstrapAdmin:DisplayName"] = enableBootstrap ? "BE1 Test Admin" : string.Empty
                };

                config.AddInMemoryCollection(settings);
            });

            if (configureTestServices is not null)
            {
                builder.ConfigureServices(configureTestServices);
            }

            if (configureLogging is not null)
            {
                builder.ConfigureLogging(configureLogging);
            }
        });
    }

    private async Task<TestSessionClient> LoginSessionAsync(
        WebApplicationFactory<Program> factory,
        string email,
        string secret)
    {
        var client = new TestSessionClient(factory, NextClientIp());
        var (csrf, _) = await client.FetchCsrfTokenAsync();

        var loginResp = await client.SendAsync(
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest(email, secret),
            csrfToken: csrf);

        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        var envelope = await loginResp.Content.ReadFromJsonAsync<ApiEnvelope<LoginResponseDto>>(JsonOptions);
        Assert.NotNull(envelope);
        client.AccessToken = envelope.Data.AccessToken;

        return client;
    }

    private async Task<(HostSummaryDto Summary, string InitialSecret)> CreateHostAsAdminAsync(
        WebApplicationFactory<Program> factory)
    {
        using var adminClient = await LoginSessionAsync(factory, _adminEmail, _adminRuntimeSecret);

        var hostEmail = $"host-{Guid.NewGuid():N}@example.invalid";
        var initialSecret = $"Host#{Guid.NewGuid():N}Aa1!";

        var createResp = await adminClient.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new CreateHostRequest(
                hostEmail,
                "Host Tốt Nghiệp",
                initialSecret));

        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        var envelope = await createResp.Content.ReadFromJsonAsync<ApiEnvelope<HostSummaryDto>>(JsonOptions);
        Assert.NotNull(envelope);

        return (envelope.Data, initialSecret);
    }

    private async Task<HostSummaryDto> LockHostAsAdminAsync(
        WebApplicationFactory<Program> factory,
        Guid hostId)
    {
        using var adminClient = await LoginSessionAsync(factory, _adminEmail, _adminRuntimeSecret);

        var lockResp = await adminClient.SendAsync(
            HttpMethod.Post,
            $"/api/admin/hosts/{hostId}/lock");

        Assert.Equal(HttpStatusCode.OK, lockResp.StatusCode);

        var envelope = await lockResp.Content.ReadFromJsonAsync<ApiEnvelope<HostSummaryDto>>(JsonOptions);
        return envelope!.Data;
    }

    private async Task<(HostSummaryDto Summary, HttpResponseMessage Response)> UnlockHostAsAdminWithResponseAsync(
        WebApplicationFactory<Program> factory,
        Guid hostId)
    {
        using var adminClient = await LoginSessionAsync(factory, _adminEmail, _adminRuntimeSecret);

        var unlockResp = await adminClient.SendAsync(
            HttpMethod.Post,
            $"/api/admin/hosts/{hostId}/unlock");

        Assert.Equal(HttpStatusCode.OK, unlockResp.StatusCode);

        var envelope = await unlockResp.Content.ReadFromJsonAsync<ApiEnvelope<HostSummaryDto>>(JsonOptions);
        return (envelope!.Data, unlockResp);
    }

    private static string MintCustomJwt(
        Guid userId,
        string email,
        string securityStamp,
        string signingKey,
        string issuer,
        string audience,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var claims = new[]
        {
            new Claim(JwtClaimNames.Sub, userId.ToString()),
            new Claim(JwtClaimNames.Email, email),
            new Claim(JwtClaimNames.Name, "Host Tốt Nghiệp"),
            new Claim(JwtClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new Claim(JwtClaimNames.Iat, issuedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
            new Claim(JwtClaimNames.SecurityStampHash, TokenCryptoHelper.ComputeSha256Hex(securityStamp)),
            new Claim(JwtClaimNames.Role, RoleNames.Host)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = issuer,
            Audience = audience,
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
                SecurityAlgorithms.HmacSha256)
        };

        return handler.CreateToken(descriptor);
    }

    private string NextClientIp()
    {
        var next = Interlocked.Increment(ref _ipOctetCounter);
        var thirdOctet = 100 + (next / 250);
        var fourthOctet = (next % 250) + 1;
        return $"198.51.{thirdOctet}.{fourthOctet}";
    }

    private sealed class FailingAddRoleExecutionSeam : IAdminHostExecutionSeam
    {
        public Task<IdentityResult> AssignHostRoleAsync(
            UserManager<ApplicationUser> userManager,
            ApplicationUser user,
            CancellationToken cancellationToken) =>
            Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "SimulatedRoleAssignmentFailure",
                Description = "Simulated failure during AddToRoleAsync to verify SQL Server transaction rollback."
            }));

        public Task OnBeforeMutateHostLockoutAsync(Guid hostId, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class ConcurrentRefreshBarrierSeam : IRefreshTokenExecutionSeam
    {
        private TaskCompletionSource<bool>? _bothArrived;
        private int _remaining;

        public void ArmForTwoConcurrentCallers()
        {
            _remaining = 2;
            _bothArrived = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        public async Task OnBeforeConditionalRotateAsync(Guid tokenId, CancellationToken cancellationToken)
        {
            var gate = _bothArrived;
            if (gate is null)
            {
                return;
            }

            if (Interlocked.Decrement(ref _remaining) <= 0)
            {
                gate.TrySetResult(true);
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                await gate.Task.WaitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                gate.TrySetResult(false);
            }
        }
    }

    private sealed class InMemoryLogCollectorProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CollectorLogger(_messages);

        public void Dispose()
        {
        }

        private sealed class CollectorLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue(formatter(state, exception));
            }
        }
    }
}
