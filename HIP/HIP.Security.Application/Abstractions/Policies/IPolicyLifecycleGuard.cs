using HIP.Security.Domain.Policies;

namespace HIP.Security.Application.Abstractions.Policies;

public interface IPolicyLifecycleGuard
{
    SecurityPolicy TransitionToSimulate(SecurityPolicy policy);
    SecurityPolicy TransitionToActive(SecurityPolicy policy);
}
