using SmartInvite.Application.Bootstrap;
using SmartInvite.Infrastructure.Persistence;
using Xunit;

namespace SmartInvite.UnitTests.Bootstrap;

public class BootstrapAndSafetyGuardTests
{
    [Fact]
    public void BootstrapValidator_WhenDisabled_SucceedsEvenWithoutFields()
    {
        var options = new BootstrapAdminOptions
        {
            Enabled = false,
            Email = string.Empty,
            Password = string.Empty,
            DisplayName = string.Empty
        };

        var result = BootstrapAdminValidator.Validate(options);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void BootstrapValidator_WhenEnabledWithCompleteValidConfig_Succeeds()
    {
        var runtimeSecret = $"Adm#{Guid.NewGuid():N}Zz9!";
        var options = new BootstrapAdminOptions
        {
            Enabled = true,
            Email = "admin-be1-test@example.invalid",
            Password = runtimeSecret,
            DisplayName = "BE1 Test Admin"
        };

        var result = BootstrapAdminValidator.Validate(options);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void BootstrapValidator_WhenEnabledWithMissingOrWeakFields_FailsWithoutLeakingSecret()
    {
        var weakSecret = "WeakSecretValue1";
        var options = new BootstrapAdminOptions
        {
            Enabled = true,
            Email = string.Empty,
            Password = weakSecret,
            DisplayName = " "
        };

        var result = BootstrapAdminValidator.Validate(options);

        Assert.True(result.IsFailure);
        Assert.Contains("BootstrapAdmin:Email", result.Error.Message);
        Assert.Contains("BootstrapAdmin:Password", result.Error.Message);
        Assert.Contains("BootstrapAdmin:DisplayName", result.Error.Message);
        Assert.DoesNotContain(weakSecret, result.Error.Message);
    }

    [Fact]
    public void BootstrapValidator_WhenDisplayNameExceedsMaxLength_FailsValidation()
    {
        var runtimeSecret = $"Adm#{Guid.NewGuid():N}Zz9!";
        var options = new BootstrapAdminOptions
        {
            Enabled = true,
            Email = "admin-be1-test@example.invalid",
            Password = runtimeSecret,
            DisplayName = new string('D', 151)
        };

        var result = BootstrapAdminValidator.Validate(options);

        Assert.True(result.IsFailure);
        Assert.Contains("BootstrapAdmin:DisplayName", result.Error.Message);
        Assert.DoesNotContain(runtimeSecret, result.Error.Message);
    }

    [Theory]
    [InlineData("Server=localhost;Database=SmartInvite_BE1_Test;Trusted_Connection=True;TrustServerCertificate=True;")]
    [InlineData("Data Source=(local);Initial Catalog=SmartInvite_Integration_Test;Integrated Security=True;")]
    public void SqlServerSafetyGuard_ValidTestDatabaseNames_Succeed(string connectionString)
    {
        var result = SqlServerConnectionSafetyGuard.ValidateTestDatabaseConnection(connectionString);

        Assert.True(result.IsSuccess);
        Assert.EndsWith("_Test", result.Value, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Server=localhost;Database=master;Trusted_Connection=True;")]
    [InlineData("Server=localhost;Database=tempdb;Trusted_Connection=True;")]
    [InlineData("Server=localhost;Database=model;Trusted_Connection=True;")]
    [InlineData("Server=localhost;Database=msdb;Trusted_Connection=True;")]
    [InlineData("Server=localhost;Database=SmartInvite;Trusted_Connection=True;")]
    [InlineData("Server=localhost;Database=SmartInvite_Dev;Trusted_Connection=True;")]
    [InlineData("Server=localhost;Database=SmartInvite_Production_Test;Trusted_Connection=True;")]
    [InlineData("Server=sql-prod.internal;Database=SmartInvite_BE1_Test;Trusted_Connection=True;")]
    public void SqlServerSafetyGuard_ForbiddenOrNonTestDatabases_FailSafely(string connectionString)
    {
        var result = SqlServerConnectionSafetyGuard.ValidateTestDatabaseConnection(connectionString);

        Assert.True(result.IsFailure);
    }
}
