using Serilog;
using SmartInvite.Api.Extensions;
using SmartInvite.Application;
using SmartInvite.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// Cấu hình Serilog từ configuration
builder.Host.UseSerilog((context, loggerConfig) =>
{
    loggerConfig
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext();
});

// Cấu hình Clean Architecture layers
builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

// Cấu hình Web API infrastructure
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddOpenApi();
builder.Services.AddApiHealthChecks();

var app = builder.Build();

app.UseSerilogRequestLogging();
app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

if (!app.Environment.IsEnvironment("Testing"))
{
    app.UseHttpsRedirection();
}

// Health check endpoints
app.MapApiHealthEndpoints();

// Endpoint nội bộ phục vụ kiểm thử exception handling trong môi trường Testing
if (app.Environment.IsEnvironment("Testing"))
{
    app.MapGet("/internal/test-error", () =>
    {
        throw new InvalidOperationException("Test exception for error handling verification.");
    }).ExcludeFromDescription();
}

await app.RunAsync();

public partial class Program;

