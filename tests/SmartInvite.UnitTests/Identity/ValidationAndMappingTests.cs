using System.Reflection;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Application.Auth;
using SmartInvite.Domain.Common;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Identity;
using Xunit;

namespace SmartInvite.UnitTests.Identity;

public class ValidationAndMappingTests
{
    [Fact]
    public void ApplicationUserCreate_SetsEmailAndDisplayName_WithMinimalSimplifiedState()
    {
        var utcNow = new DateTimeOffset(2026, 11, 1, 8, 0, 0, TimeSpan.Zero);

        var user = ApplicationUser.Create("  Host.User@Example.Invalid  ", "  Nguyễn Văn A  ", utcNow);

        Assert.NotEqual(Guid.Empty, user.Id);
        Assert.Equal("Host.User@Example.Invalid", user.Email);
        Assert.Equal("Host.User@Example.Invalid", user.UserName);
        Assert.Equal("Nguyễn Văn A", user.DisplayName);
        Assert.Equal(utcNow, user.CreatedAt);
        Assert.Null(user.LastLoginAt);
        Assert.False(user.EmailConfirmed);
        Assert.True(user.LockoutEnabled);
        Assert.Null(user.LockoutEnd);
        Assert.Null(user.PhoneNumber);
        Assert.False(user.PhoneNumberConfirmed);
        Assert.False(string.IsNullOrWhiteSpace(user.SecurityStamp));
        Assert.False(string.IsNullOrWhiteSpace(user.ConcurrencyStamp));

        var customDeclaredProperties = typeof(ApplicationUser)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["CreatedAt", "DisplayName", "LastLoginAt"], customDeclaredProperties);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ApplicationUserCreate_InvalidDisplayName_ThrowsArgumentException(string? invalidDisplayName)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            ApplicationUser.Create("host@example.invalid", invalidDisplayName!, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ApplicationUserCreate_OverlongDisplayName_ThrowsArgumentOutOfRangeException()
    {
        var overlongDisplayName = new string('N', 151);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ApplicationUser.Create("host@example.invalid", overlongDisplayName, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ValidateLogin_ValidCredentials_TrimsEmail_WithoutTrimmingPassword()
    {
        const string untrimmedInputSecret = "  Valid#Pass1234  ";
        var request = new LoginRequest("  host@example.invalid  ", untrimmedInputSecret);

        var result = AuthRequestValidator.ValidateLogin(request);

        Assert.True(result.IsSuccess);
        Assert.Equal("host@example.invalid", result.Value);
        Assert.Equal(untrimmedInputSecret, request.Password);
    }

    [Theory]
    [InlineData("", "Valid#Pass1234", "email")]
    [InlineData("not-an-email", "Valid#Pass1234", "email")]
    [InlineData("user@domain", "Valid#Pass1234", "email")]
    [InlineData("host@example.invalid", "", "password")]
    public void ValidateLogin_InvalidFields_ReturnsValidationErrorWithFieldKey(
        string email,
        string password,
        string expectedField)
    {
        var result = AuthRequestValidator.ValidateLogin(new LoginRequest(email, password));

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorCodes.ValidationError, result.Error.Code);
        Assert.NotNull(result.Error.Fields);
        Assert.True(result.Error.Fields.ContainsKey(expectedField));
    }

    [Fact]
    public void ValidateLogin_OverlongPassword_ReturnsValidationError()
    {
        var tooLongSecret = new string('A', 257);
        var result = AuthRequestValidator.ValidateLogin(new LoginRequest("host@example.invalid", tooLongSecret));

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorCodes.ValidationError, result.Error.Code);
        Assert.True(result.Error.Fields!.ContainsKey("password"));
    }

    [Theory]
    [InlineData("  host@gmail.com  ", "  Nguyễn Văn A  ")]
    [InlineData("  organizer@university.edu.vn  ", "  Ban Tổ Chức Lễ Tốt Nghiệp  ")]
    public void ValidateCreateHost_ValidInput_AllowsStandardDomains_TrimsDisplayName_AndPreservesPasswordExact(
        string rawEmail,
        string rawDisplayName)
    {
        var untrimmedSecret = $"  Host#{Guid.NewGuid():N}Aa1!  ";
        var request = new CreateHostRequest(
            Email: rawEmail,
            DisplayName: rawDisplayName,
            InitialPassword: untrimmedSecret);

        var result = AdminHostRequestValidator.ValidateCreateHost(request);

        Assert.True(result.IsSuccess);
        Assert.Equal(rawEmail.Trim(), result.Value.Email);
        Assert.Equal(rawDisplayName.Trim(), result.Value.DisplayName);
        Assert.Equal(untrimmedSecret, result.Value.InitialPassword);
    }

    [Fact]
    public void ValidateCreateHost_DisplayNameAtExact150Chars_Succeeds_AndAt151Chars_Fails()
    {
        var secret = $"Host#{Guid.NewGuid():N}Aa1!";

        var maxAllowed = AdminHostRequestValidator.ValidateCreateHost(new CreateHostRequest(
            "host@example.invalid",
            new string('A', 150),
            secret));
        Assert.True(maxAllowed.IsSuccess);

        var overLimit = AdminHostRequestValidator.ValidateCreateHost(new CreateHostRequest(
            "host@example.invalid",
            new string('A', 151),
            secret));
        Assert.True(overLimit.IsFailure);
        Assert.Equal(ErrorCodes.ValidationError, overLimit.Error.Code);
        Assert.Contains("displayName", overLimit.Error.Fields!.Keys);
    }

    [Fact]
    public void ValidateCreateHost_WeakPasswordAndInvalidFields_ReturnsFieldValidationErrors()
    {
        var request = new CreateHostRequest(
            Email: "bad-email",
            DisplayName: "   ",
            InitialPassword: "short");

        var result = AdminHostRequestValidator.ValidateCreateHost(request);

        Assert.True(result.IsFailure);
        Assert.Equal(ErrorCodes.ValidationError, result.Error.Code);
        Assert.NotNull(result.Error.Fields);
        Assert.Contains("email", result.Error.Fields.Keys);
        Assert.Contains("displayName", result.Error.Fields.Keys);
        Assert.Contains("initialPassword", result.Error.Fields.Keys);
    }

    [Fact]
    public void ValidateLockUnlockTarget_EnforcesNonEmptyId_HostRoleOnly_AndBlocksSelfOrAdmin()
    {
        var actorAdminId = Guid.NewGuid();
        var otherAdminId = Guid.NewGuid();
        var hostId = Guid.NewGuid();

        var emptyIdResult = AdminHostRequestValidator.ValidateHostId(Guid.Empty);
        Assert.True(emptyIdResult.IsFailure);
        Assert.Equal(ErrorCodes.ValidationError, emptyIdResult.Error.Code);

        var validHostTarget = AdminHostRequestValidator.ValidateLockUnlockTarget(
            targetUserId: hostId,
            actorUserId: actorAdminId,
            isTargetHost: true,
            isTargetAdmin: false);
        Assert.True(validHostTarget.IsSuccess);

        var selfTarget = AdminHostRequestValidator.ValidateLockUnlockTarget(
            targetUserId: actorAdminId,
            actorUserId: actorAdminId,
            isTargetHost: true,
            isTargetAdmin: false);
        Assert.True(selfTarget.IsFailure);
        Assert.Equal(ErrorCodes.InvalidHostOperation, selfTarget.Error.Code);

        var adminTarget = AdminHostRequestValidator.ValidateLockUnlockTarget(
            targetUserId: otherAdminId,
            actorUserId: actorAdminId,
            isTargetHost: false,
            isTargetAdmin: true);
        Assert.True(adminTarget.IsFailure);
        Assert.Equal(ErrorCodes.InvalidHostOperation, adminTarget.Error.Code);

        var dualRoleAdminTarget = AdminHostRequestValidator.ValidateLockUnlockTarget(
            targetUserId: otherAdminId,
            actorUserId: actorAdminId,
            isTargetHost: true,
            isTargetAdmin: true);
        Assert.True(dualRoleAdminTarget.IsFailure);
        Assert.Equal(ErrorCodes.InvalidHostOperation, dualRoleAdminTarget.Error.Code);

        var rolelessTarget = AdminHostRequestValidator.ValidateLockUnlockTarget(
            targetUserId: Guid.NewGuid(),
            actorUserId: actorAdminId,
            isTargetHost: false,
            isTargetAdmin: false);
        Assert.True(rolelessTarget.IsFailure);
        Assert.Equal(ErrorCodes.InvalidHostOperation, rolelessTarget.Error.Code);
    }

    [Fact]
    public void ContractsAndDtos_ShouldMatchExactApprovedMinimalFields_WithoutSensitiveOrLegacyFields()
    {
        var createRequestProps = typeof(CreateHostRequest).GetProperties()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["DisplayName", "Email", "InitialPassword"], createRequestProps);

        var authDtoProps = typeof(AuthenticatedUserDto).GetProperties()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["DisplayName", "Email", "Id", "LastLoginAt", "Roles"], authDtoProps);

        var hostDtoProps = typeof(HostSummaryDto).GetProperties()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["CreatedAt", "DisplayName", "Email", "Id", "IsLocked", "LastLoginAt"], hostDtoProps);

        var loginDtoProps = typeof(LoginResponseDto).GetProperties()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["AccessToken", "ExpiresInSeconds", "TokenType", "User"], loginDtoProps);

        var refreshDtoProps = typeof(RefreshResponseDto).GetProperties()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["AccessToken", "ExpiresInSeconds", "TokenType"], refreshDtoProps);
        Assert.DoesNotContain("RefreshToken", loginDtoProps, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("RefreshToken", refreshDtoProps, StringComparer.OrdinalIgnoreCase);

        var forbiddenPropertySubstrings = new[]
        {
            "Password",
            "SecurityStamp",
            "ConcurrencyStamp",
            "RowVersion",
            "LockoutEnd",
            "AccessFailedCount",
            "EmailConfirmed",
            "Phone",
            "Organization",
            "Status",
            "FullName",
            "HostProfile",
            "UpdatedAt",
            "Token",
            "Cookie"
        };

        foreach (var forbidden in forbiddenPropertySubstrings)
        {
            Assert.DoesNotContain(authDtoProps, p => p.Contains(forbidden, StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(hostDtoProps, p => p.Contains(forbidden, StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void UserDtoMapping_ComputesLockoutStateAccurately_AndMapsLastLoginAt()
    {
        var createdAt = new DateTimeOffset(2026, 11, 1, 8, 0, 0, TimeSpan.Zero);
        var loginAt = new DateTimeOffset(2026, 11, 1, 8, 30, 0, TimeSpan.Zero);

        var user = ApplicationUser.Create("host@gmail.com", "Nguyễn Văn A", createdAt);
        user.PasswordHash = "SENSITIVE_HASH_DO_NOT_EXPOSE";

        var initialSummary = user.ToHostSummaryDto(createdAt);
        Assert.False(initialSummary.IsLocked);
        Assert.Equal(createdAt, initialSummary.CreatedAt);
        Assert.Null(initialSummary.LastLoginAt);

        // Temporary lockout active
        user.LockoutEnd = createdAt.AddMinutes(15);
        Assert.True(user.ToHostSummaryDto(createdAt.AddMinutes(5)).IsLocked);
        Assert.False(user.ToHostSummaryDto(createdAt.AddMinutes(16)).IsLocked);

        // Permanent Admin lock
        user.LockoutEnd = DateTimeOffset.MaxValue;
        Assert.True(user.ToHostSummaryDto(loginAt).IsLocked);

        // Unlocked and logged in
        user.LockoutEnd = null;
        user.RecordLogin(loginAt);

        var authDto = user.ToAuthenticatedUserDto([RoleNames.Host, "UNEXPECTED_INTERNAL_CLAIM"]);
        var unlockedSummary = user.ToHostSummaryDto(loginAt);

        Assert.Equal(user.Id, authDto.Id);
        Assert.Equal("host@gmail.com", authDto.Email);
        Assert.Equal("Nguyễn Văn A", authDto.DisplayName);
        Assert.Equal([RoleNames.Host], authDto.Roles);
        Assert.Equal(loginAt, authDto.LastLoginAt);

        Assert.False(unlockedSummary.IsLocked);
        Assert.Equal(loginAt, unlockedSummary.LastLoginAt);
    }
}
