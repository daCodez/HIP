using HIP.Application.Certificates;
using HIP.Application.Domains;
using HIP.Domain.Domains;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Builds certification evidence only from HIP-owned persisted domain, scan, and enrollment state.</summary>
public sealed class EfManagedDomainCertificationEvidenceSource(HipDbContext dbContext)
    : IManagedDomainCertificationEvidenceSource
{
    public async Task<ManagedDomainCertificationEvidence> GetAsync(
        string domainId,
        string domainName,
        CancellationToken cancellationToken)
    {
        var domain = await dbContext.ManagedDomains.AsNoTracking()
            .SingleAsync(item => item.DomainId == domainId && item.DomainName == domainName, cancellationToken);
        var enrollment = await dbContext.DomainEnrollments.AsNoTracking()
            .Where(item => item.Domain == domainName && item.IsCurrent)
            .OrderByDescending(item => item.UpdatedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);
        var scan = await dbContext.BrowserScanResults.AsNoTracking()
            .Where(item => item.Domain == domainName)
            .OrderByDescending(item => item.LastCheckedUtc)
            .FirstOrDefaultAsync(cancellationToken);
        var websiteVerified = enrollment?.WebsiteVerifiedAtUtc ??
            (domain.VerificationMethod is HIP.Domain.Identity.VerificationMethod.HtmlFile or HIP.Domain.Identity.VerificationMethod.MetaTag
                ? domain.OwnershipVerifiedAtUtc : null);
        var dnsVerified = enrollment?.DnsVerifiedAtUtc ??
            (domain.VerificationMethod == HIP.Domain.Identity.VerificationMethod.DnsTxt ? domain.OwnershipVerifiedAtUtc : null);
        var evidence = new DomainCertificateEvidenceSnapshot(
            AccountContactVerified: enrollment?.IdentityCompletedAtUtc is not null,
            DomainControlVerifiedAtUtc: domain.OwnershipVerifiedAtUtc,
            DnsVerifiedAtUtc: dnsVerified,
            WebsiteVerifiedAtUtc: websiteVerified,
            InitialSecurityScanCompleted: scan is not null,
            UnresolvedCriticalFindings: scan?.DangerousLinksFound ?? enrollment?.UnresolvedCriticalFindings ?? 0,
            IdentityInformationCompleted: enrollment?.IdentityCompletedAtUtc is not null,
            HttpsAvailable: websiteVerified is not null,
            TlsCertificateValid: websiteVerified is not null,
            RequiredPoliciesPassed: enrollment?.SecurityReviewCompletedAtUtc is not null,
            CurrentTrustScore: scan?.Score ?? enrollment?.CurrentScore,
            DnssecStatus: domain.DnssecStatus,
            UnresolvedHighRiskFindings: scan?.SuspiciousLinksFound ?? 0,
            OrganizationIdentityVerified: enrollment?.IdentityCompletedAtUtc is not null,
            DomainTrustScore: scan?.Score,
            ScanId: scan?.ScanResultId);
        return new ManagedDomainCertificationEvidence(
            evidence,
            new DomainCertificateReviewSignals(UnresolvedHighRiskFindings: (scan?.SuspiciousLinksFound ?? 0) > 0));
    }
}
