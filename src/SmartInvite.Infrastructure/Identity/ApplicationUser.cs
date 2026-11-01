using Microsoft.AspNetCore.Identity;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Identity;

namespace SmartInvite.Infrastructure.Identity;

public sealed class ApplicationUser : IdentityUser<Guid>
{
    public ApplicationUser()
    {
    }

    public string DisplayName { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? LastLoginAt { get; private set; }

    public static ApplicationUser Create(string email, string displayName, DateTimeOffset utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        var trimmedEmail = email.Trim();
        var trimmedDisplayName = displayName.Trim();

        if (trimmedDisplayName.Length > IdentityFieldConstraints.MaxDisplayNameLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(displayName),
                $"Tên hiển thị không được vượt quá {IdentityFieldConstraints.MaxDisplayNameLength} ký tự.");
        }

        return new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = trimmedEmail,
            UserName = trimmedEmail,
            EmailConfirmed = false,
            DisplayName = trimmedDisplayName,
            CreatedAt = utcNow,
            LastLoginAt = null,
            LockoutEnabled = true,
            SecurityStamp = Guid.NewGuid().ToString("N"),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        };
    }

    public void RecordLogin(DateTimeOffset utcNow)
    {
        LastLoginAt = utcNow;
    }

    public bool IsCurrentlyLockedOut(DateTimeOffset utcNow) =>
        LockoutEnabled && LockoutEnd.HasValue && LockoutEnd.Value > utcNow;

    public AuthenticatedUserDto ToAuthenticatedUserDto(IEnumerable<string> roles)
    {
        var orderedRoles = roles
            .Where(RoleNames.IsKnownRole)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToArray();

        return new AuthenticatedUserDto(
            Id,
            Email ?? string.Empty,
            DisplayName,
            orderedRoles,
            LastLoginAt);
    }

    public HostSummaryDto ToHostSummaryDto(DateTimeOffset utcNow)
    {
        return new HostSummaryDto(
            Id,
            Email ?? string.Empty,
            DisplayName,
            IsCurrentlyLockedOut(utcNow),
            CreatedAt,
            LastLoginAt);
    }
}
