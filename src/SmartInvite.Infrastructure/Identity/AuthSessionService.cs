using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.Auth;
using SmartInvite.Domain.Common;
using SmartInvite.Infrastructure.Persistence;

namespace SmartInvite.Infrastructure.Identity;

public sealed class AuthSessionService : IAuthSessionService
{
    private static readonly ApplicationUser TimingGuardUser = new();
    private static readonly Lazy<string> TimingGuardHash = new(() =>
    {
        var hasher = new PasswordHasher<ApplicationUser>();
        var ephemeralInput = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return hasher.HashPassword(TimingGuardUser, ephemeralInput);
    });

    private static readonly Error GenericInvalidCredentialsError = Error.Unauthorized(
        ErrorCodes.InvalidCredentials,
        "Email hoặc mật khẩu không hợp lệ");

    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
    private readonly IAccessTokenService _accessTokenService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ICurrentUser _currentUser;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly ILogger<AuthSessionService> _logger;

    public AuthSessionService(
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IPasswordHasher<ApplicationUser> passwordHasher,
        IAccessTokenService accessTokenService,
        IRefreshTokenService refreshTokenService,
        ICurrentUser currentUser,
        IDateTimeProvider dateTimeProvider,
        ILogger<AuthSessionService> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _signInManager = signInManager;
        _passwordHasher = passwordHasher;
        _accessTokenService = accessTokenService;
        _refreshTokenService = refreshTokenService;
        _currentUser = currentUser;
        _dateTimeProvider = dateTimeProvider;
        _logger = logger;
    }

    public async Task<Result<LoginSessionResult>> LoginAsync(
        LoginRequest? request,
        CancellationToken cancellationToken = default)
    {
        var validation = AuthRequestValidator.ValidateLogin(request);
        if (validation.IsFailure)
        {
            return Result.Failure<LoginSessionResult>(validation.Error);
        }

        var normalizedInputEmail = validation.Value;
        var rawInputSecret = request!.Password!;

        var user = await _userManager.FindByEmailAsync(normalizedInputEmail);
        if (user is null)
        {
            PerformTimingMitigationVerify(rawInputSecret);
            _logger.LogWarning("Authentication attempt failed.");
            return Result.Failure<LoginSessionResult>(GenericInvalidCredentialsError);
        }

        var utcNow = _dateTimeProvider.UtcNow;
        if (user.IsCurrentlyLockedOut(utcNow))
        {
            PerformTimingMitigationVerify(rawInputSecret);
            _logger.LogWarning("Authentication attempt failed.");
            return Result.Failure<LoginSessionResult>(GenericInvalidCredentialsError);
        }

        var checkResult = await _signInManager.CheckPasswordSignInAsync(
            user,
            rawInputSecret,
            lockoutOnFailure: true);

        if (!checkResult.Succeeded)
        {
            if (checkResult.IsLockedOut || checkResult.IsNotAllowed)
            {
                PerformTimingMitigationVerify(rawInputSecret);
            }

            _logger.LogWarning("Authentication attempt failed.");
            return Result.Failure<LoginSessionResult>(GenericInvalidCredentialsError);
        }

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            if (string.IsNullOrWhiteSpace(user.SecurityStamp))
            {
                var stampInit = await _userManager.UpdateSecurityStampAsync(user);
                if (!stampInit.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result.Failure<LoginSessionResult>(Error.Internal());
                }
            }

            user.RecordLogin(utcNow);
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);

                var isConcurrency = updateResult.Errors.Any(e =>
                    string.Equals(e.Code, nameof(IdentityErrorDescriber.ConcurrencyFailure), StringComparison.Ordinal));

                if (isConcurrency)
                {
                    return Result.Failure<LoginSessionResult>(Error.Conflict(
                        ErrorCodes.ConcurrencyConflict,
                        "Trạng thái tài khoản vừa thay đổi đồng thời. Vui lòng đăng nhập lại."));
                }

                return Result.Failure<LoginSessionResult>(Error.Internal());
            }

            var roles = await _userManager.GetRolesAsync(user);
            var userDto = user.ToAuthenticatedUserDto(roles);

            var refreshResult = await _refreshTokenService.IssueAsync(user.Id, utcNow, cancellationToken);
            var jwtResult = _accessTokenService.CreateAccessToken(
                new AccessTokenSubject(
                    user.Id,
                    user.Email ?? string.Empty,
                    user.DisplayName,
                    userDto.Roles,
                    user.SecurityStamp!),
                utcNow);

            await transaction.CommitAsync(cancellationToken);

            _logger.LogInformation(
                "User authenticated successfully. UserId: {UserId}, RefreshFamilyId: {RefreshFamilyId}",
                user.Id,
                refreshResult.FamilyId);

            var response = new LoginResponseDto(
                AccessToken: jwtResult.AccessToken,
                TokenType: AuthTokenConstants.BearerTokenType,
                ExpiresInSeconds: jwtResult.ExpiresInSeconds,
                User: userDto);

            return Result.Success(new LoginSessionResult(
                Response: response,
                RawRefreshToken: refreshResult.RawToken,
                RefreshTokenExpiresAt: refreshResult.ExpiresAt));
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task<Result<RefreshSessionResult>> RefreshAsync(
        string? rawRefreshToken,
        CancellationToken cancellationToken = default)
    {
        var utcNow = _dateTimeProvider.UtcNow;
        var rotationResult = await _refreshTokenService.RotateSessionAsync(
            rawRefreshToken,
            utcNow,
            cancellationToken);

        if (rotationResult.IsFailure)
        {
            return Result.Failure<RefreshSessionResult>(rotationResult.Error);
        }

        var rotated = rotationResult.Value;

        return Result.Success(new RefreshSessionResult(
            Response: rotated.Response,
            RawRefreshToken: rotated.ReplacementRefreshToken.RawToken,
            RefreshTokenExpiresAt: rotated.ReplacementRefreshToken.ExpiresAt));
    }

    public async Task<Result<LogoutResponseDto>> LogoutAsync(
        string? rawRefreshToken,
        CancellationToken cancellationToken = default)
    {
        var utcNow = _dateTimeProvider.UtcNow;

        await _refreshTokenService.RevokeByRawTokenAsync(
            rawRefreshToken,
            RefreshTokenRevokeReasons.Logout,
            utcNow,
            cancellationToken);

        _logger.LogInformation("Refresh session signed out.");

        return Result.Success(new LogoutResponseDto(SignedOut: true));
    }

    public async Task<Result<LogoutResponseDto>> LogoutAllAsync(CancellationToken cancellationToken = default)
    {
        if (!_currentUser.IsAuthenticated || _currentUser.UserId is not Guid userId)
        {
            return Result.Failure<LogoutResponseDto>(Error.Unauthorized(
                ErrorCodes.AuthenticationRequired,
                "Yêu cầu xác thực để thực hiện thao tác này."));
        }

        var utcNow = _dateTimeProvider.UtcNow;
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user is null ||
            await _userManager.IsLockedOutAsync(user) ||
            user.IsCurrentlyLockedOut(utcNow))
        {
            return Result.Failure<LogoutResponseDto>(Error.Unauthorized(
                ErrorCodes.AuthenticationRequired,
                "Phiên đăng nhập không còn hiệu lực."));
        }

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            await _refreshTokenService.RevokeAllForUserAsync(
                user.Id,
                RefreshTokenRevokeReasons.LogoutAll,
                utcNow,
                cancellationToken);

            var stampResult = await _userManager.UpdateSecurityStampAsync(user);
            if (!stampResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);

                var isConcurrency = stampResult.Errors.Any(e =>
                    string.Equals(e.Code, nameof(IdentityErrorDescriber.ConcurrencyFailure), StringComparison.Ordinal));

                if (isConcurrency)
                {
                    return Result.Failure<LogoutResponseDto>(Error.Conflict(
                        ErrorCodes.ConcurrencyConflict,
                        "Trạng thái tài khoản vừa thay đổi đồng thời. Vui lòng thử lại."));
                }

                return Result.Failure<LogoutResponseDto>(Error.Internal("Không thể thu hồi toàn bộ phiên đăng nhập."));
            }

            await transaction.CommitAsync(cancellationToken);

            _logger.LogInformation("All sessions revoked for user. UserId: {UserId}", user.Id);

            return Result.Success(new LogoutResponseDto(SignedOut: true));
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task<Result<AuthenticatedUserDto>> GetCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;

        if (!_currentUser.IsAuthenticated || _currentUser.UserId is not Guid userId)
        {
            return Result.Failure<AuthenticatedUserDto>(Error.Unauthorized(
                ErrorCodes.AuthenticationRequired,
                "Yêu cầu xác thực để thực hiện thao tác này."));
        }

        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user is null ||
            await _userManager.IsLockedOutAsync(user) ||
            user.IsCurrentlyLockedOut(_dateTimeProvider.UtcNow))
        {
            return Result.Failure<AuthenticatedUserDto>(Error.Unauthorized(
                ErrorCodes.AuthenticationRequired,
                "Phiên đăng nhập không còn hiệu lực."));
        }

        var roles = await _userManager.GetRolesAsync(user);

        return Result.Success(user.ToAuthenticatedUserDto(roles));
    }

    private void PerformTimingMitigationVerify(string rawInputSecret)
    {
        _ = _passwordHasher.VerifyHashedPassword(TimingGuardUser, TimingGuardHash.Value, rawInputSecret);
    }
}
