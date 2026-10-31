using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace SmartInvite.Infrastructure.Persistence;

public class DatabaseHealthCheck : IHealthCheck
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IConfiguration _configuration;

    public DatabaseHealthCheck(ApplicationDbContext dbContext, IConfiguration configuration)
    {
        _dbContext = dbContext;
        _configuration = configuration;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var connectionString = _configuration.GetConnectionString("SmartInviteDatabase");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return HealthCheckResult.Degraded("Chuỗi kết nối cơ sở dữ liệu 'SmartInviteDatabase' chưa được cấu hình.");
        }

        try
        {
            var canConnect = await _dbContext.Database.CanConnectAsync(cancellationToken);
            return canConnect
                ? HealthCheckResult.Healthy("Kết nối cơ sở dữ liệu SQL Server sẵn sàng.")
                : HealthCheckResult.Unhealthy("Không thể kết nối đến cơ sở dữ liệu SQL Server.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Lỗi khi kiểm tra kết nối cơ sở dữ liệu SQL Server.", ex);
        }
    }
}

