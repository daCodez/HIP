using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IAppealService
{
    AppealRequest Submit(AppealRequest appeal);

    IReadOnlyCollection<AppealRequest> List();

    AppealRequest? Get(string appealId);

    AppealRequest Approve(string appealId, string reviewerId, string reason);

    AppealRequest Reject(string appealId, string reviewerId, string reason);

    AppealRequest RequestMoreInfo(string appealId, string reviewerId, string reason);

    Task<AppealRequest> SubmitAsync(AppealRequest appeal, CancellationToken cancellationToken) =>
        Task.FromResult(Submit(appeal));

    Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult(List());

    Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken) =>
        Task.FromResult(Get(appealId));

    Task<AppealRequest> ApproveAsync(string appealId, string reviewerId, string reason, CancellationToken cancellationToken) =>
        Task.FromResult(Approve(appealId, reviewerId, reason));

    Task<AppealRequest> RejectAsync(string appealId, string reviewerId, string reason, CancellationToken cancellationToken) =>
        Task.FromResult(Reject(appealId, reviewerId, reason));

    Task<AppealRequest> RequestMoreInfoAsync(string appealId, string reviewerId, string reason, CancellationToken cancellationToken) =>
        Task.FromResult(RequestMoreInfo(appealId, reviewerId, reason));
}
