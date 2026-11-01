namespace SmartInvite.Application.AdminHosts;

public sealed record CreateHostRequest(
    string? Email,
    string? DisplayName,
    string? InitialPassword);

public sealed record HostSummaryDto(
    Guid Id,
    string Email,
    string DisplayName,
    bool IsLocked,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastLoginAt);
