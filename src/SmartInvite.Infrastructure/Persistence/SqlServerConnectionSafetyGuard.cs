using Microsoft.Data.SqlClient;
using SmartInvite.Domain.Common;

namespace SmartInvite.Infrastructure.Persistence;

public static class SqlServerConnectionSafetyGuard
{
    private static readonly HashSet<string> ForbiddenSystemDatabases = new(StringComparer.OrdinalIgnoreCase)
    {
        "master",
        "tempdb",
        "model",
        "msdb"
    };

    private static readonly string[] ForbiddenProductionMarkers =
    [
        "prod",
        "production",
        "live",
        "staging"
    ];

    public static Result<string> ValidateTestDatabaseConnection(string? connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return Result.Failure<string>(Error.Validation(
                "Chưa cấu hình biến môi trường ConnectionStrings__SmartInviteDatabase cho cơ sở dữ liệu kiểm thử."));
        }

        SqlConnectionStringBuilder builder;
        try
        {
            builder = new SqlConnectionStringBuilder(connectionString);
        }
        catch (ArgumentException)
        {
            return Result.Failure<string>(Error.Validation(
                "Định dạng chuỗi kết nối SQL Server kiểm thử không hợp lệ."));
        }

        var databaseName = builder.InitialCatalog?.Trim();
        if (string.IsNullOrWhiteSpace(databaseName))
        {
            return Result.Failure<string>(Error.Validation(
                "Chuỗi kết nối kiểm thử bắt buộc phải chỉ định rõ tên Database/Initial Catalog."));
        }

        if (ForbiddenSystemDatabases.Contains(databaseName))
        {
            return Result.Failure<string>(Error.Validation(
                $"Từ chối chạy kiểm thử trên cơ sở dữ liệu hệ thống SQL Server '{databaseName}'."));
        }

        var dataSource = builder.DataSource ?? string.Empty;
        foreach (var marker in ForbiddenProductionMarkers)
        {
            if (databaseName.Contains(marker, StringComparison.OrdinalIgnoreCase) ||
                dataSource.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return Result.Failure<string>(Error.Validation(
                    "Từ chối chuỗi kết nối có dấu hiệu môi trường production/staging."));
            }
        }

        if (!databaseName.EndsWith("_Test", StringComparison.OrdinalIgnoreCase))
        {
            return Result.Failure<string>(Error.Validation(
                $"Tên cơ sở dữ liệu '{databaseName}' không kết thúc bằng '_Test'. Chỉ cho phép chạy kiểm thử trên test database rõ ràng."));
        }

        return Result.Success(databaseName);
    }
}
