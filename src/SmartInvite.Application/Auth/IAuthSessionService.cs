using SmartInvite.Domain.Common;

namespace SmartInvite.Application.Auth;

public interface IAuthSessionService
{
    Task<Result<LoginSessionResult>> LoginAsync(LoginRequest? request, CancellationToken cancellationToken = default);
    Task<Result<RefreshSessionResult>> RefreshAsync(string? rawRefreshToken, CancellationToken cancellationToken = default);
    Task<Result<LogoutResponseDto>> LogoutAsync(string? rawRefreshToken, CancellationToken cancellationToken = default);
    Task<Result<LogoutResponseDto>> LogoutAllAsync(CancellationToken cancellationToken = default);
    Task<Result<AuthenticatedUserDto>> GetCurrentUserAsync(CancellationToken cancellationToken = default);
}
