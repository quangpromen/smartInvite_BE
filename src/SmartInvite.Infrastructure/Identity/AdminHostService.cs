using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Domain.Common;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Persistence;

namespace SmartInvite.Infrastructure.Identity;

internal interface IAdminHostExecutionSeam
{
    Task<IdentityResult> AssignHostRoleAsync(
        UserManager<ApplicationUser> userManager,
        ApplicationUser user,
        CancellationToken cancellationToken);

    Task OnBeforeMutateHostLockoutAsync(Guid hostId, CancellationToken cancellationToken);
}

internal sealed class DefaultAdminHostExecutionSeam : IAdminHostExecutionSeam
{
    public Task<IdentityResult> AssignHostRoleAsync(
        UserManager<ApplicationUser> userManager,
        ApplicationUser user,
        CancellationToken cancellationToken) =>
        userManager.AddToRoleAsync(user, RoleNames.Host);

    public Task OnBeforeMutateHostLockoutAsync(Guid hostId, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}

public sealed class AdminHostService : IAdminHostService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ICurrentUser _currentUser;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly IAdminHostExecutionSeam _executionSeam;
    private readonly ILogger<AdminHostService> _logger;

    public AdminHostService(
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        ICurrentUser currentUser,
        IDateTimeProvider dateTimeProvider,
        ILogger<AdminHostService> logger)
        : this(
            dbContext,
            userManager,
            roleManager,
            currentUser,
            dateTimeProvider,
            new DefaultAdminHostExecutionSeam(),
            logger)
    {
    }

    internal AdminHostService(
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        ICurrentUser currentUser,
        IDateTimeProvider dateTimeProvider,
        IAdminHostExecutionSeam executionSeam,
        ILogger<AdminHostService> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _roleManager = roleManager;
        _currentUser = currentUser;
        _dateTimeProvider = dateTimeProvider;
        _executionSeam = executionSeam;
        _logger = logger;
    }

    public async Task<Result<HostSummaryDto>> CreateHostAsync(
        CreateHostRequest? request,
        CancellationToken cancellationToken = default)
    {
        var actorResult = EnsureAdminActor();
        if (actorResult.IsFailure)
        {
            return Result.Failure<HostSummaryDto>(actorResult.Error);
        }

        var validation = AdminHostRequestValidator.ValidateCreateHost(request);
        if (validation.IsFailure)
        {
            return Result.Failure<HostSummaryDto>(validation.Error);
        }

        var input = validation.Value;

        var existingUser = await _userManager.FindByEmailAsync(input.Email);
        if (existingUser is not null)
        {
            return Result.Failure<HostSummaryDto>(Error.Conflict(
                ErrorCodes.EmailAlreadyExists,
                "Email đã được sử dụng cho một tài khoản khác."));
        }

        var utcNow = _dateTimeProvider.UtcNow;
        var user = ApplicationUser.Create(input.Email, input.DisplayName, utcNow);

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            if (!await _roleManager.RoleExistsAsync(RoleNames.Host))
            {
                var createRoleResult = await _roleManager.CreateAsync(new IdentityRole<Guid>(RoleNames.Host)
                {
                    Id = Guid.NewGuid(),
                    ConcurrencyStamp = Guid.NewGuid().ToString()
                });

                if (!createRoleResult.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return Result.Failure<HostSummaryDto>(Error.Internal("Không thể khởi tạo vai trò HOST."));
                }
            }

            var createUserResult = await _userManager.CreateAsync(user, input.InitialPassword);
            if (!createUserResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);

                if (HasDuplicateIdentityError(createUserResult))
                {
                    return Result.Failure<HostSummaryDto>(Error.Conflict(
                        ErrorCodes.EmailAlreadyExists,
                        "Email đã được sử dụng cho một tài khoản khác."));
                }

                if (HasPasswordError(createUserResult))
                {
                    return Result.Failure<HostSummaryDto>(Error.Validation(
                        "Dữ liệu tạo Host không hợp lệ.",
                        new Dictionary<string, string[]>
                        {
                            ["initialPassword"] = ["Mật khẩu khởi tạo không đáp ứng chính sách bảo mật yêu cầu."]
                        }));
                }

                return Result.Failure<HostSummaryDto>(Error.Internal("Không thể tạo tài khoản Host."));
            }

            var addRoleResult = await _executionSeam.AssignHostRoleAsync(_userManager, user, cancellationToken);
            if (!addRoleResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                return Result.Failure<HostSummaryDto>(Error.Internal("Không thể gán vai trò HOST cho tài khoản."));
            }

            await transaction.CommitAsync(cancellationToken);

            _logger.LogInformation(
                "Admin created Host account. ActorId: {ActorId}, TargetUserId: {TargetUserId}",
                actorResult.Value,
                user.Id);

            return Result.Success(user.ToHostSummaryDto(utcNow));
        }
        catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
        {
            await transaction.RollbackAsync(cancellationToken);
            return Result.Failure<HostSummaryDto>(Error.Conflict(
                ErrorCodes.EmailAlreadyExists,
                "Email đã được sử dụng cho một tài khoản khác."));
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task<Result<HostSummaryDto>> LockHostAsync(
        Guid hostId,
        CancellationToken cancellationToken = default)
    {
        var targetResult = await LoadAndValidateTargetHostAsync(hostId);
        if (targetResult.IsFailure)
        {
            return Result.Failure<HostSummaryDto>(targetResult.Error);
        }

        var (actorId, user) = targetResult.Value;

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            await _executionSeam.OnBeforeMutateHostLockoutAsync(user.Id, cancellationToken);

            if (!user.LockoutEnabled)
            {
                var enableResult = await _userManager.SetLockoutEnabledAsync(user, true);
                if (!enableResult.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return MapIdentityMutationFailure(enableResult, "Không thể kích hoạt cơ chế khóa cho tài khoản Host.");
                }
            }

            var lockEndResult = await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
            if (!lockEndResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                return MapIdentityMutationFailure(lockEndResult, "Không thể khóa tài khoản Host.");
            }

            var stampResult = await _userManager.UpdateSecurityStampAsync(user);
            if (!stampResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                return MapIdentityMutationFailure(stampResult, "Không thể thu hồi phiên đăng nhập của tài khoản Host.");
            }

            var lockAtUtc = _dateTimeProvider.UtcNow;
            await _dbContext.RefreshTokens
                .Where(t => t.UserId == user.Id && t.RevokedAt == null)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(t => t.RevokedAt, lockAtUtc)
                        .SetProperty(t => t.RevokedReason, RefreshTokenRevokeReasons.AdminLocked),
                    cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            _logger.LogInformation(
                "Admin locked Host account. ActorId: {ActorId}, TargetUserId: {TargetUserId}",
                actorId,
                user.Id);

            return Result.Success(user.ToHostSummaryDto(lockAtUtc));
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Result.Failure<HostSummaryDto>(Error.Conflict(
                ErrorCodes.ConcurrencyConflict,
                "Tài khoản Host đã bị thay đổi bởi một thao tác đồng thời khác. Vui lòng thử lại."));
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    public async Task<Result<HostSummaryDto>> UnlockHostAsync(
        Guid hostId,
        CancellationToken cancellationToken = default)
    {
        var targetResult = await LoadAndValidateTargetHostAsync(hostId);
        if (targetResult.IsFailure)
        {
            return Result.Failure<HostSummaryDto>(targetResult.Error);
        }

        var (actorId, user) = targetResult.Value;

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            await _executionSeam.OnBeforeMutateHostLockoutAsync(user.Id, cancellationToken);

            if (!user.LockoutEnabled)
            {
                var enableResult = await _userManager.SetLockoutEnabledAsync(user, true);
                if (!enableResult.Succeeded)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    return MapIdentityMutationFailure(enableResult, "Không thể đồng bộ cấu hình khóa cho tài khoản Host.");
                }
            }

            var unlockResult = await _userManager.SetLockoutEndDateAsync(user, null);
            if (!unlockResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                return MapIdentityMutationFailure(unlockResult, "Không thể mở khóa tài khoản Host.");
            }

            var resetFailedCountResult = await _userManager.ResetAccessFailedCountAsync(user);
            if (!resetFailedCountResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                return MapIdentityMutationFailure(resetFailedCountResult, "Không thể đặt lại bộ đếm đăng nhập sai của tài khoản Host.");
            }

            var stampResult = await _userManager.UpdateSecurityStampAsync(user);
            if (!stampResult.Succeeded)
            {
                await transaction.RollbackAsync(cancellationToken);
                return MapIdentityMutationFailure(stampResult, "Không thể cập nhật dấu bảo mật của tài khoản Host.");
            }

            await transaction.CommitAsync(cancellationToken);

            _logger.LogInformation(
                "Admin unlocked Host account. ActorId: {ActorId}, TargetUserId: {TargetUserId}",
                actorId,
                user.Id);

            return Result.Success(user.ToHostSummaryDto(_dateTimeProvider.UtcNow));
        }
        catch (DbUpdateConcurrencyException)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Result.Failure<HostSummaryDto>(Error.Conflict(
                ErrorCodes.ConcurrencyConflict,
                "Tài khoản Host đã bị thay đổi bởi một thao tác đồng thời khác. Vui lòng thử lại."));
        }
        catch
        {
            await transaction.RollbackAsync(cancellationToken);
            throw;
        }
    }

    private async Task<Result<(Guid ActorId, ApplicationUser TargetUser)>> LoadAndValidateTargetHostAsync(Guid hostId)
    {
        var actorResult = EnsureAdminActor();
        if (actorResult.IsFailure)
        {
            return Result.Failure<(Guid, ApplicationUser)>(actorResult.Error);
        }

        var idValidation = AdminHostRequestValidator.ValidateHostId(hostId);
        if (idValidation.IsFailure)
        {
            return Result.Failure<(Guid, ApplicationUser)>(idValidation.Error);
        }

        var actorId = actorResult.Value;
        var user = await _userManager.FindByIdAsync(hostId.ToString());
        if (user is null)
        {
            return Result.Failure<(Guid, ApplicationUser)>(Error.NotFound(
                ErrorCodes.HostNotFound,
                "Không tìm thấy tài khoản Host."));
        }

        var roles = await _userManager.GetRolesAsync(user);
        var isTargetHost = roles.Contains(RoleNames.Host, StringComparer.Ordinal);
        var isTargetAdmin = roles.Contains(RoleNames.Admin, StringComparer.Ordinal);

        var targetValidation = AdminHostRequestValidator.ValidateLockUnlockTarget(
            user.Id,
            actorId,
            isTargetHost,
            isTargetAdmin);

        if (targetValidation.IsFailure)
        {
            return Result.Failure<(Guid, ApplicationUser)>(targetValidation.Error);
        }

        return Result.Success((actorId, user));
    }

    private Result<Guid> EnsureAdminActor()
    {
        if (!_currentUser.IsAuthenticated || _currentUser.UserId is not Guid actorId)
        {
            return Result.Failure<Guid>(Error.Unauthorized(
                ErrorCodes.AuthenticationRequired,
                "Yêu cầu xác thực để thực hiện thao tác này."));
        }

        if (!_currentUser.IsInRole(RoleNames.Admin))
        {
            return Result.Failure<Guid>(Error.Forbidden());
        }

        return Result.Success(actorId);
    }

    private static Result<HostSummaryDto> MapIdentityMutationFailure(IdentityResult result, string internalMessage)
    {
        if (HasConcurrencyError(result))
        {
            return Result.Failure<HostSummaryDto>(Error.Conflict(
                ErrorCodes.ConcurrencyConflict,
                "Tài khoản Host đã bị thay đổi bởi một thao tác đồng thời khác. Vui lòng thử lại."));
        }

        return Result.Failure<HostSummaryDto>(Error.Internal(internalMessage));
    }

    private static bool HasDuplicateIdentityError(IdentityResult result) =>
        result.Errors.Any(e =>
            string.Equals(e.Code, nameof(IdentityErrorDescriber.DuplicateEmail), StringComparison.Ordinal) ||
            string.Equals(e.Code, nameof(IdentityErrorDescriber.DuplicateUserName), StringComparison.Ordinal));

    private static bool HasPasswordError(IdentityResult result) =>
        result.Errors.Any(e => e.Code.StartsWith("Password", StringComparison.Ordinal));

    private static bool HasConcurrencyError(IdentityResult result) =>
        result.Errors.Any(e =>
            string.Equals(e.Code, nameof(IdentityErrorDescriber.ConcurrencyFailure), StringComparison.Ordinal));

    private static bool IsUniqueConstraintViolation(DbUpdateException exception) =>
        exception.InnerException is SqlException sqlEx && (sqlEx.Number == 2601 || sqlEx.Number == 2627);
}
