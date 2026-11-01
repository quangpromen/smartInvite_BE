using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.Bootstrap;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Persistence;

namespace SmartInvite.Infrastructure.Identity;

public sealed class AdminBootstrapService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly IConfiguration _configuration;
    private readonly IOptions<BootstrapAdminOptions> _options;
    private readonly ILogger<AdminBootstrapService> _logger;

    public AdminBootstrapService(
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        IDateTimeProvider dateTimeProvider,
        IConfiguration configuration,
        IOptions<BootstrapAdminOptions> options,
        ILogger<AdminBootstrapService> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _roleManager = roleManager;
        _dateTimeProvider = dateTimeProvider;
        _configuration = configuration;
        _options = options;
        _logger = logger;
    }

    public async Task ExecuteAsync(CancellationToken cancellationToken = default)
    {
        var config = _options.Value;
        var validation = BootstrapAdminValidator.Validate(config);
        if (validation.IsFailure)
        {
            throw new InvalidOperationException(validation.Error.Message);
        }

        if (!config.Enabled)
        {
            return;
        }

        var connectionString = _configuration.GetConnectionString("SmartInviteDatabase");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "BootstrapAdmin được bật nhưng chưa cấu hình chuỗi kết nối 'ConnectionStrings:SmartInviteDatabase'.");
        }

        await EnsureDatabaseMigratedAsync(cancellationToken);

        await EnsureRoleExistsAsync(RoleNames.Admin);
        await EnsureRoleExistsAsync(RoleNames.Host);

        var trimmedEmail = config.Email.Trim();
        var trimmedDisplayName = config.DisplayName.Trim();

        var existingUser = await _userManager.FindByEmailAsync(trimmedEmail);
        if (existingUser is not null)
        {
            if (await _userManager.IsInRoleAsync(existingUser, RoleNames.Host))
            {
                throw new InvalidOperationException(
                    "Tài khoản được chỉ định cho BootstrapAdmin đang có vai trò HOST; không thể cấp quyền ADMIN.");
            }

            if (!await _userManager.IsInRoleAsync(existingUser, RoleNames.Admin))
            {
                var roleAssignResult = await _userManager.AddToRoleAsync(existingUser, RoleNames.Admin);
                if (!roleAssignResult.Succeeded)
                {
                    throw new InvalidOperationException("Không thể gán vai trò ADMIN cho tài khoản BootstrapAdmin hiện có.");
                }
            }

            _logger.LogInformation("Bootstrap Admin verified idempotently. UserId: {UserId}", existingUser.Id);
            return;
        }

        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        var adminUser = ApplicationUser.Create(trimmedEmail, trimmedDisplayName, _dateTimeProvider.UtcNow);
        var createResult = await _userManager.CreateAsync(adminUser, config.Password);
        if (!createResult.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            var errorCodes = string.Join(", ", createResult.Errors.Select(e => e.Code));
            throw new InvalidOperationException(
                $"Không thể khởi tạo tài khoản BootstrapAdmin. Mã lỗi Identity: {errorCodes}.");
        }

        var addAdminRoleResult = await _userManager.AddToRoleAsync(adminUser, RoleNames.Admin);
        if (!addAdminRoleResult.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            throw new InvalidOperationException("Không thể gán vai trò ADMIN cho tài khoản BootstrapAdmin mới.");
        }

        await transaction.CommitAsync(cancellationToken);

        _logger.LogInformation("Bootstrap Admin created successfully. UserId: {UserId}", adminUser.Id);
    }

    private async Task EnsureDatabaseMigratedAsync(CancellationToken cancellationToken)
    {
        if (!await _dbContext.Database.CanConnectAsync(cancellationToken))
        {
            throw new InvalidOperationException(
                "Không thể kết nối đến cơ sở dữ liệu SQL Server để thực hiện BootstrapAdmin.");
        }

        var appliedMigrations = (await _dbContext.Database.GetAppliedMigrationsAsync(cancellationToken)).ToList();
        var pendingMigrations = (await _dbContext.Database.GetPendingMigrationsAsync(cancellationToken)).ToList();

        if (appliedMigrations.Count == 0 || pendingMigrations.Count > 0)
        {
            throw new InvalidOperationException(
                "Cơ sở dữ liệu chưa được áp dụng đầy đủ EF Core migration. Hệ thống không tự động chạy migration khi khởi động.");
        }
    }

    private async Task EnsureRoleExistsAsync(string roleName)
    {
        if (await _roleManager.RoleExistsAsync(roleName))
        {
            return;
        }

        var result = await _roleManager.CreateAsync(new IdentityRole<Guid>(roleName)
        {
            Id = Guid.NewGuid(),
            ConcurrencyStamp = Guid.NewGuid().ToString()
        });

        if (!result.Succeeded)
        {
            var isDuplicate = result.Errors.Any(e =>
                string.Equals(e.Code, nameof(IdentityErrorDescriber.DuplicateRoleName), StringComparison.Ordinal));

            if (!isDuplicate)
            {
                throw new InvalidOperationException($"Không thể tạo vai trò hệ thống '{roleName}'.");
            }
        }
    }
}

public sealed class AdminBootstrapHostedService : IHostedService
{
    private readonly IServiceScopeFactory _scopeFactory;

    public AdminBootstrapHostedService(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var bootstrapService = scope.ServiceProvider.GetRequiredService<AdminBootstrapService>();
        await bootstrapService.ExecuteAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
