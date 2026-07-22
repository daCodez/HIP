using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public sealed record DomainVerificationRecheckSummary(int Examined, int Rechecked, int Failed);

public interface IDomainVerificationLifecycleCoordinator
{
    Task<DomainVerificationRecheckSummary> RecheckDueAsync(int maximum, CancellationToken cancellationToken);
}

/// <summary>Runs bounded scheduled rechecks without reading or exposing challenge tokens.</summary>
public sealed class DomainVerificationLifecycleCoordinator(
    IWebsiteIdentityRepository identities,
    IWebsiteIdentityService service,
    DomainVerificationLifecycleOptions? lifecycleOptions = null,
    TimeProvider? timeProvider = null) : IDomainVerificationLifecycleCoordinator
{
    private readonly DomainVerificationLifecycleOptions lifecycle =
        (lifecycleOptions ?? DomainVerificationLifecycleOptions.Default).Validate();
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<DomainVerificationRecheckSummary> RecheckDueAsync(
        int maximum,
        CancellationToken cancellationToken)
    {
        if (maximum is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maximum));
        }

        var dueBefore = clock.GetUtcNow().Subtract(lifecycle.VerifiedRecheckInterval);
        var due = (await identities.ListAsync(cancellationToken).ConfigureAwait(false))
            .Where(identity => identity.VerificationStatus == VerificationStatus.Verified)
            .Where(identity => identity.PreferredVerificationMethod == VerificationMethod.DnsTxt)
            .Where(identity => (identity.LastCheckedAtUtc ?? identity.VerifiedAtUtc ?? identity.CreatedAtUtc) <= dueBefore)
            .OrderBy(identity => identity.LastCheckedAtUtc ?? identity.VerifiedAtUtc ?? identity.CreatedAtUtc)
            .Take(maximum)
            .ToArray();
        var rechecked = 0;
        var failed = 0;
        foreach (var identity in due)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await service.RetryVerificationAsync(
                    identity.Domain,
                    "system:domain-verification-recheck",
                    "Owner",
                    cancellationToken).ConfigureAwait(false);
                rechecked++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                failed++;
            }
        }

        return new DomainVerificationRecheckSummary(due.Length, rechecked, failed);
    }
}
