using System.Net;
using SmartInvite.IntegrationTests.Common;
using Xunit;

namespace SmartInvite.IntegrationTests.Health;

public class HealthCheckTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public HealthCheckTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task LiveHealthCheck_ShouldReturnOk_AndHealthyStatus()
    {
        // Act
        var response = await _client.GetAsync("/health/live");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"status\":\"Healthy\"", content);
        Assert.Contains("self", content);
    }

    [Fact]
    public async Task ReadyHealthCheck_WhenDatabaseNotConfigured_ShouldReturnClearStatusWithoutCrashing()
    {
        // Act
        var response = await _client.GetAsync("/health/ready");

        // Assert - Không crash, trả về trạng thái rõ ràng (200 với Degraded hoặc trạng thái rõ ràng)
        var content = await response.Content.ReadAsStringAsync();
        Assert.NotEmpty(content);
        Assert.Contains("SmartInviteDatabase", content);
    }
}

