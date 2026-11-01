using SmartInvite.Application.Abstractions;
using SmartInvite.Domain.Identity;

namespace SmartInvite.Application.Security;

public static class AuthorizationPolicies
{
    public const string Authenticated = "Authenticated";
    public const string AdminOnly = "AdminOnly";
    public const string HostOnly = "HostOnly";
}

public sealed class ResourceOwnershipGuard : IResourceOwnershipGuard
{
    private readonly ICurrentUser _currentUser;

    public ResourceOwnershipGuard(ICurrentUser currentUser)
    {
        _currentUser = currentUser;
    }

    public bool IsOwner(Guid ownerId) =>
        ownerId != Guid.Empty &&
        _currentUser.IsAuthenticated &&
        _currentUser.IsInRole(RoleNames.Host) &&
        _currentUser.UserId == ownerId;

    public bool IsOwner(IOwnedResource resource)
    {
        ArgumentNullException.ThrowIfNull(resource);
        return IsOwner(resource.OwnerId);
    }
}
