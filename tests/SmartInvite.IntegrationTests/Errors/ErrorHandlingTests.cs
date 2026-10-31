using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using SmartInvite.Api.Common;
using SmartInvite.IntegrationTests.Common;
using Xunit;

namespace SmartInvite.IntegrationTests.Errors;

public class ErrorHandlingTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly CustomWebApplicationFactory _factory;
    private readonly HttpClient _client;

    public ErrorHandlingTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task UnhandledException_ShouldReturnUnifiedErrorEnvelope_WithoutStackTrace()
    {
        // Act
        var response = await _client.GetAsync("/internal/test-error");

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var envelope = JsonSerializer.Deserialize<ErrorEnvelope>(content, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        Assert.NotNull(envelope);
        Assert.NotNull(envelope.Error);
        Assert.Equal("INTERNAL_ERROR", envelope.Error.Code);
        Assert.Equal("Đã xảy ra lỗi không mong muốn", envelope.Error.Message);
        Assert.False(string.IsNullOrWhiteSpace(envelope.Error.TraceId));

        // Đảm bảo không lộ stack trace hay tên ngoại lệ nội bộ
        Assert.DoesNotContain("InvalidOperationException", content);
        Assert.DoesNotContain("StackTrace", content);
        Assert.DoesNotContain("at Program", content);
    }

    [Fact]
    public async Task ProductionEnvironment_ShouldNotExposeInternalTestEndpoint()
    {
        // Arrange
        using var prodClient = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
        }).CreateClient();

        // Act
        var response = await prodClient.GetAsync("/internal/test-error");

        // Assert - Endpoint test nội bộ không được mở trong Production
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
