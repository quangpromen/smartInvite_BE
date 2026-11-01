using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.Auth;
using SmartInvite.Domain.Common;

namespace SmartInvite.Infrastructure.Identity;

internal interface IAccessTokenStateValidator
{
    Task<bool> IsPrincipalActiveAsync(ClaimsPrincipal? principal, CancellationToken cancellationToken = default);
}

internal sealed class AccessTokenStateValidator : IAccessTokenStateValidator
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IDateTimeProvider _dateTimeProvider;

    public AccessTokenStateValidator(
        UserManager<ApplicationUser> userManager,
        IDateTimeProvider dateTimeProvider)
    {
        _userManager = userManager;
        _dateTimeProvider = dateTimeProvider;
    }

    public async Task<bool> IsPrincipalActiveAsync(
        ClaimsPrincipal? principal,
        CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;

        if (principal?.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        var rawSub = principal.FindFirst(JwtClaimNames.Sub)?.Value
                     ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (!Guid.TryParse(rawSub, out var userId) || userId == Guid.Empty)
        {
            return false;
        }

        var tokenStampHash = principal.FindFirst(JwtClaimNames.SecurityStampHash)?.Value;
        if (string.IsNullOrWhiteSpace(tokenStampHash))
        {
            return false;
        }

        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user is null || string.IsNullOrWhiteSpace(user.SecurityStamp))
        {
            return false;
        }

        var utcNow = _dateTimeProvider.UtcNow;
        if (await _userManager.IsLockedOutAsync(user) || user.IsCurrentlyLockedOut(utcNow))
        {
            return false;
        }

        return TokenCryptoHelper.FixedTimeEqualsSha256Hex(tokenStampHash, user.SecurityStamp);
    }
}

internal sealed class JwtOptionsValidation : IValidateOptions<JwtOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        var result = JwtOptionsValidator.Validate(options);
        return result.IsSuccess
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(result.Error.Message);
    }
}

internal sealed class JwtBearerOptionsSetup : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IOptions<JwtOptions> _jwtOptions;

    public JwtBearerOptionsSetup(IOptions<JwtOptions> jwtOptions)
    {
        _jwtOptions = jwtOptions;
    }

    public void Configure(JwtBearerOptions options) =>
        Configure(JwtBearerDefaults.AuthenticationScheme, options);

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (!string.Equals(name, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return;
        }

        var jwt = _jwtOptions.Value;
        var keyValidation = JwtOptionsValidator.ValidateAndResolveSigningKey(jwt);
        if (keyValidation.IsFailure)
        {
            throw new InvalidOperationException(keyValidation.Error.Message);
        }

        options.MapInboundClaims = false;
        options.SaveToken = false;
        options.RequireHttpsMetadata = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer.Trim(),
            ValidateAudience = true,
            ValidAudience = jwt.Audience.Trim(),
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyValidation.Value),
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.FromSeconds(jwt.ClockSkewSeconds),
            NameClaimType = JwtClaimNames.Name,
            RoleClaimType = JwtClaimNames.Role
        };

        options.Events = BearerAuthenticationEvents.Create();
    }
}

public static class BearerAuthenticationEvents
{
    private static readonly IReadOnlyDictionary<string, string[]> EmptyFields =
        new Dictionary<string, string[]>();

    public static JwtBearerEvents Create() =>
        new()
        {
            OnTokenValidated = async context =>
            {
                var stateValidator = context.HttpContext.RequestServices
                    .GetRequiredService<IAccessTokenStateValidator>();

                var isActive = await stateValidator.IsPrincipalActiveAsync(
                    context.Principal,
                    context.HttpContext.RequestAborted);

                if (!isActive)
                {
                    context.Fail("Access token is no longer valid.");
                }
            },
            OnChallenge = async context =>
            {
                context.HandleResponse();
                if (context.Response.HasStarted)
                {
                    return;
                }

                context.Response.Headers.WWWAuthenticate = AuthTokenConstants.BearerTokenType;

                await WriteAuthErrorAsync(
                    context.HttpContext,
                    StatusCodes.Status401Unauthorized,
                    ErrorCodes.AuthenticationRequired,
                    "Yêu cầu xác thực để thực hiện thao tác này.");
            },
            OnForbidden = async context =>
            {
                if (context.Response.HasStarted)
                {
                    return;
                }

                await WriteAuthErrorAsync(
                    context.HttpContext,
                    StatusCodes.Status403Forbidden,
                    ErrorCodes.Forbidden,
                    "Bạn không có quyền truy cập tài nguyên này.");
            }
        };

    private static Task WriteAuthErrorAsync(
        HttpContext httpContext,
        int statusCode,
        string code,
        string message)
    {
        var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;

        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.ContentType = "application/json";

        var payload = new
        {
            error = new
            {
                code,
                message,
                fields = EmptyFields,
                traceId
            }
        };

        return httpContext.Response.WriteAsJsonAsync(payload, httpContext.RequestAborted);
    }
}

