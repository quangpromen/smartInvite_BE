namespace SmartInvite.Application.Abstractions;

public interface IOwnedResource
{
    Guid OwnerId { get; }
}

public interface IResourceOwnershipGuard
{
    bool IsOwner(Guid ownerId);
    bool IsOwner(IOwnedResource resource);
}
