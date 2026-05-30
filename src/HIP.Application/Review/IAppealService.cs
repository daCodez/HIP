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
}
