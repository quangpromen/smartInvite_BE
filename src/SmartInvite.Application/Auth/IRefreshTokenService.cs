using SmartInvite.Domain.Common;

namespace SmartInvite.Application.Auth;

public sealed record RotatedRefreshSession(
    RefreshResponseDto Response,
    IssuedRefreshTokenResult ReplacementRefreshToken);

public interface IRefreshTokenService
{
    Task<IssuedRefreshTokenResult> IssueAsync(
        Guid userId,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);

    Task<Result<RotatedRefreshSession>> RotateSessionAsync(
        string? rawRefreshToken,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);

    Task RevokeByRawTokenAsync(
        string? rawRefreshToken,
        string reason,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);

    Task RevokeAllForUserAsync(
        Guid userId,
        string reason,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);
}

