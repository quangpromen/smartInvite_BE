using System.Globalization;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SmartInvite.Application.Auth;
using SmartInvite.Domain.Identity;

namespace SmartInvite.Infrastructure.Identity;

public sealed class JwtAccessTokenService : IAccessTokenService
{
    private static readonly JsonWebTokenHandler TokenHandler = new()
    {
        SetDefaultTimesOnTokenCreation = false
    };

    private readonly IOptions<JwtOptions> _jwtOptions;

    public JwtAccessTokenService(IOptions<JwtOptions> jwtOptions)
    {
        _jwtOptions = jwtOptions;
    }

    public JwtTokenResult CreateAccessToken(AccessTokenSubject subject, DateTimeOffset issuedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(subject);

        if (subject.UserId == Guid.Empty)
        {
            throw new ArgumentException("UserId không được rỗng.", nameof(subject));
        }

        if (string.IsNullOrWhiteSpace(subject.Email))
        {
            throw new ArgumentException("Email của người dùng không được rỗng.", nameof(subject));
        }

        if (string.IsNullOrWhiteSpace(subject.DisplayName))
        {
            throw new ArgumentException("DisplayName của người dùng không được rỗng.", nameof(subject));
        }

        if (string.IsNullOrWhiteSpace(subject.SecurityStamp))
        {
            throw new ArgumentException("SecurityStamp của người dùng không được rỗng.", nameof(subject));
        }

        var options = _jwtOptions.Value;
        var keyValidation = JwtOptionsValidator.ValidateAndResolveSigningKey(options);
        if (keyValidation.IsFailure)
        {
            throw new InvalidOperationException(keyValidation.Error.Message);
        }

        var expiresAtUtc = issuedAtUtc.AddMinutes(options.AccessTokenMinutes);
        var expiresInSeconds = options.AccessTokenMinutes * 60;
        var securityStampHash = TokenCryptoHelper.ComputeSha256Hex(subject.SecurityStamp);

        var approvedRoles = subject.Roles
            .Where(RoleNames.IsKnownRole)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToArray();

        var claims = new List<Claim>(6 + approvedRoles.Length)
        {
            new(JwtClaimNames.Sub, subject.UserId.ToString()),
            new(JwtClaimNames.Email, subject.Email.Trim()),
            new(JwtClaimNames.Name, subject.DisplayName.Trim()),
            new(JwtClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(
                JwtClaimNames.Iat,
                issuedAtUtc.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64),
            new(JwtClaimNames.SecurityStampHash, securityStampHash)
        };

        foreach (var role in approvedRoles)
        {
            claims.Add(new Claim(JwtClaimNames.Role, role));
        }

        var signingKey = new SymmetricSecurityKey(keyValidation.Value);
        var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = options.Issuer.Trim(),
            Audience = options.Audience.Trim(),
            IssuedAt = issuedAtUtc.UtcDateTime,
            NotBefore = issuedAtUtc.UtcDateTime,
            Expires = expiresAtUtc.UtcDateTime,
            SigningCredentials = signingCredentials
        };

        var accessToken = TokenHandler.CreateToken(descriptor);

        return new JwtTokenResult(
            AccessToken: accessToken,
            ExpiresInSeconds: expiresInSeconds,
            ExpiresAt: expiresAtUtc);
    }
}
