using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SmartInvite.Application.Auth;
using SmartInvite.Domain.Common;
using SmartInvite.Infrastructure.Persistence;

namespace SmartInvite.Infrastructure.Identity;

internal interface IRefreshTokenExecutionSeam
{
    Task OnBeforeConditionalRotateAsync(Guid tokenId, CancellationToken cancellationToken);
}

internal sealed class DefaultRefreshTokenExecutionSeam : IRefreshTokenExecutionSeam
{
    public Task OnBeforeConditionalRotateAsync(Guid tokenId, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}

public sealed class RefreshTokenService : IRefreshTokenService
{
    private const int MaxRawRefreshTokenLength = 512;

    private static readonly Error GenericInvalidRefreshTokenError = Error.Unauthorized(
        ErrorCodes.InvalidRefreshToken,
        "Phiên làm mới không hợp lệ hoặc đã hết hạn.");

    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAccessTokenService _accessTokenService;
    private readonly IOptions<JwtOptions> _jwtOptions;
    private readonly IRefreshTokenExecutionSeam _executionSeam;
    private readonly ILogger<RefreshTokenService> _logger;

    public RefreshTokenService(
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        IAccessTokenService accessTokenService,
        IOptions<JwtOptions> jwtOptions,
        ILogger<RefreshTokenService> logger)
        : this(
            dbContext,
            userManager,
            accessTokenService,
            jwtOptions,
            new DefaultRefreshTokenExecutionSeam(),
            logger)
    {
    }

    internal RefreshTokenService(
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        IAccessTokenService accessTokenService,
        IOptions<JwtOptions> jwtOptions,
        IRefreshTokenExecutionSeam executionSeam,
        ILogger<RefreshTokenService> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _accessTokenService = accessTokenService;
        _jwtOptions = jwtOptions;
        _executionSeam = executionSeam;
        _logger = logger;
    }

    public async Task<IssuedRefreshTokenResult> IssueAsync(
        Guid userId,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("UserId không được rỗng.", nameof(userId));
        }

        var options = _jwtOptions.Value;
        var rawToken = TokenCryptoHelper.GenerateSecureRefreshToken();
        var tokenHash = TokenCryptoHelper.ComputeSha256Hex(rawToken);
        var familyId = Guid.NewGuid();
        var expiresAt = utcNow.AddDays(options.RefreshTokenDays);

        var entity = RefreshToken.Create(
            userId: userId,
            tokenHash: tokenHash,
            familyId: familyId,
            createdAt: utcNow,
            expiresAt: expiresAt);

        _dbContext.RefreshTokens.Add(entity);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return new IssuedRefreshTokenResult(
            TokenId: entity.Id,
            FamilyId: entity.FamilyId,
            RawToken: rawToken,
            ExpiresAt: entity.ExpiresAt);
    }

    public async Task<Result<RotatedRefreshSession>> RotateSessionAsync(
        string? rawRefreshToken,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawRefreshToken) || rawRefreshToken.Length > MaxRawRefreshTokenLength)
        {
            _logger.LogWarning("Refresh attempt rejected: missing or malformed refresh cookie.");
            return Result.Failure<RotatedRefreshSession>(GenericInvalidRefreshTokenError);
        }

        var incomingHash = TokenCryptoHelper.ComputeSha256Hex(rawRefreshToken);

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            var existingToken = await _dbContext.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.TokenHash == incomingHash, cancellationToken);

            if (existingToken is null)
            {
                await transaction.RollbackAsync(cancellationToken);
                _logger.LogWarning("Refresh attempt rejected: unrecognized refresh token.");
                return Result.Failure<RotatedRefreshSession>(GenericInvalidRefreshTokenError);
            }

            if (existingToken.IsRotated || existingToken.IsRevoked)
            {
                var revokedCount = await _dbContext.RefreshTokens
                    .Where(t => t.FamilyId == existingToken.FamilyId && t.RevokedAt == null)
                    .ExecuteUpdateAsync(
                        setters => setters
                            .SetProperty(t => t.RevokedAt, utcNow)
                            .SetProperty(t => t.RevokedReason, RefreshTokenRevokeReasons.ReuseDetected),
                        cancellationToken);

                await transaction.CommitAsync(cancellationToken);

                _logger.LogWarning(
                    "Refresh token reuse detected ({SecurityErrorCode}). Revoked token family. UserId: {UserId}, FamilyId: {FamilyId}, TokenId: {TokenId}, RevokedCount: {RevokedCount}",
                    ErrorCodes.RefreshTokenReused,
                    existingToken.UserId,
                    existingToken.FamilyId,
                    existingToken.Id,
                    revokedCount);

                return Result.Failure<RotatedRefreshSession>(GenericInvalidRefreshTokenError);
            }

            if (existingToken.IsExpired(utcNow))
            {
                await transaction.RollbackAsync(cancellationToken);
                _logger.LogWarning(
                    "Refresh attempt rejected: expired refresh token. UserId: {UserId}, TokenId: {TokenId}",
                    existingToken.UserId,
                    existingToken.Id);
                return Result.Failure<RotatedRefreshSession>(GenericInvalidRefreshTokenError);
            }

            var user = await _userManager.FindByIdAsync(existingToken.UserId.ToString());
            if (user is null ||
                string.IsNullOrWhiteSpace(user.SecurityStamp) ||
                await _userManager.IsLockedOutAsync(user) ||
                user.IsCurrentlyLockedOut(utcNow))
            {
                await _dbContext.RefreshTokens
                    .Where(t => t.FamilyId == existingToken.FamilyId && t.RevokedAt == null)
                    .ExecuteUpdateAsync(
                        setters => setters
                            .SetProperty(t => t.RevokedAt, utcNow)
                            .SetProperty(t => t.RevokedReason, RefreshTokenRevokeReasons.AccountUnavailable),
                        cancellationToken);

                await transaction.CommitAsync(cancellationToken);

                _logger.LogWarning(
                    "Refresh attempt rejected: target user unavailable or locked. UserId: {UserId}, FamilyId: {FamilyId}",
                    existingToken.UserId,
                    existingToken.FamilyId);

                return Result.Failure<RotatedRefreshSession>(GenericInvalidRefreshTokenError);
            }

            await _executionSeam.OnBeforeConditionalRotateAsync(existingToken.Id, cancellationToken);

            var replacementRawToken = TokenCryptoHelper.GenerateSecureRefreshToken();
            var replacementHash = TokenCryptoHelper.ComputeSha256Hex(replacementRawToken);
            var replacementExpiresAt = utcNow.AddDays(_jwtOptions.Value.RefreshTokenDays);

            var replacementEntity = RefreshToken.Create(
                userId: user.Id,
                tokenHash: replacementHash,
                familyId: existingToken.FamilyId,
                createdAt: utcNow,
                expiresAt: replacementExpiresAt);

            var rowsAffected = await _dbContext.RefreshTokens
                .Where(t =>
                    t.Id == existingToken.Id &&
                    t.RotatedAt == null &&
                    t.RevokedAt == null &&
                    t.ExpiresAt > utcNow)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(t => t.RotatedAt, utcNow)
                        .SetProperty(t => t.ReplacedByTokenId, replacementEntity.Id),
                    cancellationToken);

            if (rowsAffected != 1)
            {
                await transaction.RollbackAsync(cancellationToken);

                _logger.LogWarning(
                    "Concurrent refresh token rotation lost race. UserId: {UserId}, FamilyId: {FamilyId}, TokenId: {TokenId}",
                    existingToken.UserId,
                    existingToken.FamilyId,
                    existingToken.Id);

                return Result.Failure<RotatedRefreshSession>(GenericInvalidRefreshTokenError);
            }

            _dbContext.RefreshTokens.Add(replacementEntity);
            await _dbContext.SaveChangesAsync(cancellationToken);

            var roles = await _userManager.GetRolesAsync(user);
            var jwtResult = _accessTokenService.CreateAccessToken(
                new AccessTokenSubject(
                    user.Id,
                    user.Email ?? string.Empty,
                    user.DisplayName,
                    roles.ToArray(),
                    user.SecurityStamp),
                utcNow);

            await transaction.CommitAsync(cancellationToken);

            _logger.LogInformation(
                "Refresh token rotated successfully. UserId: {UserId}, FamilyId: {FamilyId}, OldTokenId: {OldTokenId}, NewTokenId: {NewTokenId}",
                user.Id,
                existingToken.FamilyId,
                existingToken.Id,
                replacementEntity.Id);

            var response = new RefreshResponseDto(
                AccessToken: jwtResult.AccessToken,
                TokenType: AuthTokenConstants.BearerTokenType,
                ExpiresInSeconds: jwtResult.ExpiresInSeconds);

            var replacementResult = new IssuedRefreshTokenResult(
                TokenId: replacementEntity.Id,
                FamilyId: replacementEntity.FamilyId,
                RawToken: replacementRawToken,
                ExpiresAt: replacementExpiresAt);

            return Result.Success(new RotatedRefreshSession(response, replacementResult));
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task RevokeByRawTokenAsync(
        string? rawRefreshToken,
        string reason,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        if (string.IsNullOrWhiteSpace(rawRefreshToken) || rawRefreshToken.Length > MaxRawRefreshTokenLength)
        {
            return;
        }

        var tokenHash = TokenCryptoHelper.ComputeSha256Hex(rawRefreshToken);

        await _dbContext.RefreshTokens
            .Where(t => t.TokenHash == tokenHash && t.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(t => t.RevokedAt, utcNow)
                    .SetProperty(t => t.RevokedReason, reason.Trim()),
                cancellationToken);
    }

    public async Task RevokeAllForUserAsync(
        Guid userId,
        string reason,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        if (userId == Guid.Empty)
        {
            return;
        }

        await _dbContext.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(t => t.RevokedAt, utcNow)
                    .SetProperty(t => t.RevokedReason, reason.Trim()),
                cancellationToken);
    }
}

