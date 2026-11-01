using SmartInvite.Api.Common;
using SmartInvite.Application.Security;

namespace SmartInvite.Api.Endpoints;

public static class InternalTestingEndpoints
{
    public static IEndpointRouteBuilder MapInternalTestingEndpoints(
        this IEndpointRouteBuilder endpoints,
        IWebHostEnvironment environment)
    {
        if (!environment.IsEnvironment("Testing"))
        {
            return endpoints;
        }

        endpoints.MapGet("/internal/test-error", () =>
        {
            throw new InvalidOperationException("Test exception for error handling verification.");
        }).ExcludeFromDescription();

        endpoints.MapGet("/internal/test-host-only", () =>
            Results.Ok(new ApiEnvelope<string>("host-access-granted")))
            .RequireAuthorization(AuthorizationPolicies.HostOnly)
            .ExcludeFromDescription();

        return endpoints;
    }
}
