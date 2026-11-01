using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SmartInvite.IntegrationTests.Common;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    public const string TestRemoteIpHeader = "X-Test-Remote-Ip";

    public static readonly string TestJwtSigningKey = Convert.ToBase64String(
        SHA256.HashData("SmartInvite.BE1.IntegrationTests.DeterministicSigningSeed.v1"u8));

    public CustomWebApplicationFactory()
    {
        ClientOptions.BaseAddress = new Uri("https://localhost");
        ClientOptions.AllowAutoRedirect = false;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "SmartInvite.Api",
                ["Jwt:Audience"] = "SmartInvite.Web",
                ["Jwt:SigningKey"] = TestJwtSigningKey,
                ["Jwt:AccessTokenMinutes"] = "15",
                ["Jwt:RefreshTokenDays"] = "7",
                ["Jwt:ClockSkewSeconds"] = "30"
            });
        });

        builder.ConfigureServices(services =>
        {
            services.AddTransient<IStartupFilter, TestRemoteIpStartupFilter>();
        });
    }

    private sealed class TestRemoteIpStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.Use(async (context, nextMiddleware) =>
                {
                    if (context.Request.Headers.TryGetValue(TestRemoteIpHeader, out var ipValues) &&
                        IPAddress.TryParse(ipValues.ToString(), out var parsedIp))
                    {
                        context.Connection.RemoteIpAddress = parsedIp;
                    }
                    else
                    {
                        context.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                    }

                    await nextMiddleware();
                });

                next(app);
            };
        }
    }
}
