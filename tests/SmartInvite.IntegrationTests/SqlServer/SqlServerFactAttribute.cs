using Xunit;

namespace SmartInvite.IntegrationTests.SqlServer;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class SqlServerFactAttribute : FactAttribute
{
    public const string ConnectionStringEnvVar = "ConnectionStrings__SmartInviteDatabase";

    public SqlServerFactAttribute()
    {
        var connectionString = Environment.GetEnvironmentVariable(ConnectionStringEnvVar);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            Skip = "Chưa cấu hình biến môi trường ConnectionStrings__SmartInviteDatabase cho SQL Server test database (*_Test).";
        }
    }
}
