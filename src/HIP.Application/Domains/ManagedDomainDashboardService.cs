using HIP.Domain.Certificates;
using HIP.Domain.Domains;

namespace HIP.Application.Domains;

/// <summary>Server-owned evidence joined to one authorization-filtered managed domain.</summary>
public sealed record ManagedDomainDashboardEvidence(
    string? OrganizationName,
    int? HipScore,
    DomainCertificateLevel? CertificationLevel,
    DomainCertificateStatus? CertificateStatus,
    DateTimeOffset? CertificateExpiresAtUtc,
    string? PublicCertificateNumber,
    bool? HttpsAvailable,
    DateTimeOffset? LastScanAtUtc,
    int HighRiskFindingCount,
    int CriticalFindingCount,
    IReadOnlyCollection<string> RequiredRemediation,
    DateTimeOffset? NextReviewAtUtc);

/// <summary>Persistence projection for unified managed-domain dashboard data.</summary>
public interface IManagedDomainDashboardDataSource
{
    /// <summary>Returns privacy-safe dashboard evidence for one already-authorized stable domain.</summary>
    Task<ManagedDomainDashboardEvidence> GetAsync(
        string domainId,
        string domainName,
        CancellationToken cancellationToken);
}

/// <summary>Unified owner dashboard row for one authorized managed domain.</summary>
public sealed record ManagedDomainDashboardSummary(
    string DomainId,
    string DomainName,
    string? OrganizationId,
    string? OrganizationName,
    DomainAccessRole AccessRole,
    ManagedDomainStatus DomainStatus,
    ManagedDomainVerificationStatus VerificationStatus,
    DateTimeOffset? OwnershipVerifiedAtUtc,
    DomainDnssecStatus DnssecStatus,
    int? HipScore,
    DomainCertificateLevel? CertificationLevel,
    DomainCertificateStatus? CertificateStatus,
    DateTimeOffset? CertificateExpiresAtUtc,
    string? PublicCertificateNumber,
    string BadgeStatus,
    bool? HttpsAvailable,
    DateTimeOffset? LastScanAtUtc,
    int SecurityFindingCount,
    IReadOnlyCollection<string> ActionRequired,
    DateTimeOffset? NextReviewAtUtc,
    DateTimeOffset UpdatedAtUtc);

/// <summary>Builds unified domain dashboard rows after centralized membership authorization.</summary>
public sealed class ManagedDomainDashboardService(
    IDomainManagementService domainManagement,
    IManagedDomainDashboardDataSource dataSource,
    TimeProvider timeProvider)
{
    /// <summary>Lists dashboard data only for domains visible to the authenticated actor.</summary>
    public async Task<IReadOnlyCollection<ManagedDomainDashboardSummary>> ListAsync(
        string actorId,
        ManagedDomainQuery query,
        CancellationToken cancellationToken)
    {
        var domains = await domainManagement.ListAsync(actorId, query, cancellationToken).ConfigureAwait(false);
        var result = new List<ManagedDomainDashboardSummary>(domains.Count);
        foreach (var domain in domains)
        {
            var evidence = await dataSource.GetAsync(domain.DomainId, domain.DomainName, cancellationToken).ConfigureAwait(false);
            result.Add(Summary(domain, evidence, timeProvider.GetUtcNow()));
        }
        return result;
    }

    private static ManagedDomainDashboardSummary Summary(
        ManagedDomainAccessView domain,
        ManagedDomainDashboardEvidence evidence,
        DateTimeOffset now)
    {
        var actions = new List<string>();
        if (domain.Status == ManagedDomainStatus.ActionRequired)
            actions.Add("Review the domain status and complete the required action.");
        if (domain.VerificationStatus != ManagedDomainVerificationStatus.Verified)
            actions.Add("Verify domain ownership.");
        if (domain.DnssecStatus is DomainDnssecStatus.Invalid or DomainDnssecStatus.Misconfigured)
            actions.Add("Repair the DNSSEC configuration.");
        if (evidence.CriticalFindingCount > 0)
            actions.Add("Resolve critical security findings.");
        actions.AddRange(evidence.RequiredRemediation.Where(item => !string.IsNullOrWhiteSpace(item)));
        if (evidence.CertificateStatus is { } status && status != DomainCertificateStatus.Active)
            actions.Add($"Certificate status is {status}.");
        if (evidence.CertificateExpiresAtUtc is { } expiresAt && expiresAt <= now.AddDays(30))
            actions.Add("Renew the certificate before it expires.");

        var badgeStatus = evidence.CertificateStatus == DomainCertificateStatus.Active &&
            evidence.CertificateExpiresAtUtc is { } expiry && expiry > now
            ? "Live"
            : "Unavailable";
        return new ManagedDomainDashboardSummary(
            domain.DomainId, domain.DomainName, domain.OrganizationId, evidence.OrganizationName,
            domain.AccessRole, domain.Status, domain.VerificationStatus, domain.OwnershipVerifiedAtUtc,
            domain.DnssecStatus, evidence.HipScore, evidence.CertificationLevel, evidence.CertificateStatus,
            evidence.CertificateExpiresAtUtc, evidence.PublicCertificateNumber, badgeStatus,
            evidence.HttpsAvailable, evidence.LastScanAtUtc,
            checked(evidence.HighRiskFindingCount + evidence.CriticalFindingCount),
            actions.Distinct(StringComparer.Ordinal).ToArray(), evidence.NextReviewAtUtc, domain.UpdatedAtUtc);
    }
}
