using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IReputationOverrideService
{
    ReputationOverrideRequest Request(ReputationOverrideRequest request);

    IReadOnlyCollection<ReputationOverrideRequest> List();

    ReputationOverrideRequest Approve(string overrideRequestId, string approvedBy, string reason);

    ReputationOverrideRequest Reject(string overrideRequestId, string rejectedBy, string reason);

    int CalculateRequiredApprovalCount(int currentScore, int requestedScore);
}
