namespace HIP.Application.Identity;

/// <summary>Bounded domain-verification challenge and recheck policy.</summary>
public sealed record DomainVerificationLifecycleOptions(
    TimeSpan ChallengeLifetime,
    TimeSpan VerifiedRecheckInterval)
{
    public static DomainVerificationLifecycleOptions Default { get; } =
        new(TimeSpan.FromHours(24), TimeSpan.FromDays(7));

    public DomainVerificationLifecycleOptions Validate()
    {
        if (ChallengeLifetime < TimeSpan.FromMinutes(10) ||
            ChallengeLifetime > TimeSpan.FromDays(7) ||
            VerifiedRecheckInterval < TimeSpan.FromHours(1) ||
            VerifiedRecheckInterval > TimeSpan.FromDays(30))
        {
            throw new InvalidOperationException("Domain verification lifecycle intervals are outside HIP safety bounds.");
        }

        return this;
    }
}
