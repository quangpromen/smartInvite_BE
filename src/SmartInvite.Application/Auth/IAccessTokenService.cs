namespace SmartInvite.Application.Auth;

public sealed record AccessTokenSubject(
    Guid UserId,
    string Email,
    string DisplayName,
    IReadOnlyCollection<string> Roles,
    string SecurityStamp);

public interface IAccessTokenService
{
    JwtTokenResult CreateAccessToken(AccessTokenSubject subject, DateTimeOffset issuedAtUtc);
}

