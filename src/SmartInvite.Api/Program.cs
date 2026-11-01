using Serilog;
using SmartInvite.Api.Endpoints;
using SmartInvite.Api.Extensions;
using SmartInvite.Application;
using SmartInvite.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

if (!builder.Environment.IsEnvironment("Testing"))
{
    builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true);
    builder.Configuration.AddEnvironmentVariables();
}

builder.Host.UseSerilog((context, loggerConfig) =>
{
    loggerConfig
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext();
});

builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

builder.Services.Configure<RouteHandlerOptions>(options =>
{
    options.ThrowOnBadRequest = true;
});

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddApiOpenApi();
builder.Services.AddApiHealthChecks();
builder.Services.AddApiCors();
builder.Services.AddApiRateLimiting();
builder.Services.AddApiCsrfProtection();

var app = builder.Build();

app.UseSerilogRequestLogging();
app.UseExceptionHandler();

if (!app.Environment.IsEnvironment("Testing"))
{
    app.UseHttpsRedirection();
}

if (app.Environment.IsDevelopment())
{
    app.UseApiOpenApi();
}

app.UseCors(CorsExtensions.PolicyName);
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseCsrfProtection();
app.UseAntiforgery();

app.MapApiHealthEndpoints();
app.MapAuthEndpoints();
app.MapAdminHostEndpoints();
app.MapInternalTestingEndpoints(app.Environment);

await app.RunAsync();

public partial class Program;
