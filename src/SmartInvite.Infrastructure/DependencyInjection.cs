using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.AdminHosts;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Bootstrap;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Identity;
using SmartInvite.Infrastructure.Persistence;
using SmartInvite.Infrastructure.Services;

namespace SmartInvite.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        _ = configuration;

        services.AddDbContext<ApplicationDbContext>((serviceProvider, options) =>
        {
            var runtimeConfig = serviceProvider.GetRequiredService<IConfiguration>();
            var connectionString = runtimeConfig.GetConnectionString("SmartInviteDatabase");

            if (!string.IsNullOrWhiteSpace(connectionString))
            {
                options.UseSqlServer(connectionString);
            }
            else
            {
                options.UseSqlServer();
            }
        });

        services
            .AddIdentityCore<ApplicationUser>(options =>
            {
                options.Password.RequiredLength = IdentityFieldConstraints.MinPasswordLength;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireDigit = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredUniqueChars = IdentityFieldConstraints.RequiredUniquePasswordChars;

                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = IdentityFieldConstraints.AllowedUserNameCharacters;

                options.SignIn.RequireConfirmedEmail = false;

                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            })
            .AddRoles<IdentityRole<Guid>>()
            .AddSignInManager<SignInManager<ApplicationUser>>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

        services.AddOptions<JwtOptions>()
            .BindConfiguration(JwtOptions.SectionName)
            .ValidateOnStart();

        services.AddSingleton<IValidateOptions<JwtOptions>, JwtOptionsValidation>();
        services.ConfigureOptions<JwtBearerOptionsSetup>();

        services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer();

        services.AddAuthorizationBuilder()
            .AddPolicy(AuthorizationPolicies.Authenticated, policy =>
                policy.RequireAuthenticatedUser())
            .AddPolicy(AuthorizationPolicies.AdminOnly, policy =>
                policy.RequireAuthenticatedUser().RequireRole(RoleNames.Admin))
            .AddPolicy(AuthorizationPolicies.HostOnly, policy =>
                policy.RequireAuthenticatedUser().RequireRole(RoleNames.Host));

        services.AddOptions<BootstrapAdminOptions>()
            .BindConfiguration(BootstrapAdminOptions.SectionName);

        services.AddHttpContextAccessor();
        services.AddSingleton<IDateTimeProvider, DateTimeProvider>();
        services.AddSingleton<IAdminHostExecutionSeam, DefaultAdminHostExecutionSeam>();
        services.AddSingleton<IRefreshTokenExecutionSeam, DefaultRefreshTokenExecutionSeam>();
        services.AddSingleton<IAccessTokenService, JwtAccessTokenService>();
        services.AddScoped<IAccessTokenStateValidator, AccessTokenStateValidator>();
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();
        services.AddScoped<ICurrentUser, CurrentUser>();
        services.AddScoped<IAuthSessionService, AuthSessionService>();
        services.AddScoped<IAdminHostService, AdminHostService>();
        services.AddScoped<AdminBootstrapService>();
        services.AddHostedService<AdminBootstrapHostedService>();

        services.AddHealthChecks()
            .AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);

        return services;
    }
}
