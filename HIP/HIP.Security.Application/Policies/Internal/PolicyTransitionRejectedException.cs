namespace HIP.Security.Application.Policies.Internal;

public sealed class PolicyTransitionRejectedException(string message, PolicyTransitionRejectReasonCode reasonCode)
    : InvalidOperationException(message)
{
    public PolicyTransitionRejectReasonCode ReasonCode { get; } = reasonCode;
}
