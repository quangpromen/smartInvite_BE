using Microsoft.Extensions.DependencyInjection;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.Security;

namespace SmartInvite.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddScoped<IResourceOwnershipGuard, ResourceOwnershipGuard>();

        return services;
    }
}
