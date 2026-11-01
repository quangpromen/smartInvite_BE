namespace SmartInvite.Application.Auth;

public static class AuthTokenConstants
{
    public const string BearerTokenType = "Bearer";
}

public sealed record CsrfTokenDto(string RequestToken);

public sealed record LoginRequest(string? Email, string? Password);

public sealed record AuthenticatedUserDto(
    Guid Id,
    string Email,
    string DisplayName,
    IReadOnlyList<string> Roles,
    DateTimeOffset? LastLoginAt);

public sealed record LoginResponseDto(
    string AccessToken,
    string TokenType,
    int ExpiresInSeconds,
    AuthenticatedUserDto User);

public sealed record RefreshResponseDto(
    string AccessToken,
    string TokenType,
    int ExpiresInSeconds);

public sealed record LogoutResponseDto(bool SignedOut);

public sealed record JwtTokenResult(
    string AccessToken,
    int ExpiresInSeconds,
    DateTimeOffset ExpiresAt);

public sealed record IssuedRefreshTokenResult(
    Guid TokenId,
    Guid FamilyId,
    string RawToken,
    DateTimeOffset ExpiresAt);

public sealed record LoginSessionResult(
    LoginResponseDto Response,
    string RawRefreshToken,
    DateTimeOffset RefreshTokenExpiresAt);

public sealed record RefreshSessionResult(
    RefreshResponseDto Response,
    string RawRefreshToken,
    DateTimeOffset RefreshTokenExpiresAt);
