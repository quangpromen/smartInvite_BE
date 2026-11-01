using SmartInvite.Domain.Common;

namespace SmartInvite.Application.AdminHosts;

public interface IAdminHostService
{
    Task<Result<HostSummaryDto>> CreateHostAsync(CreateHostRequest? request, CancellationToken cancellationToken = default);
    Task<Result<HostSummaryDto>> LockHostAsync(Guid hostId, CancellationToken cancellationToken = default);
    Task<Result<HostSummaryDto>> UnlockHostAsync(Guid hostId, CancellationToken cancellationToken = default);
}
