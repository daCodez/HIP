using System.Text.Json;
using HIP.Application.Domains;
using HIP.Domain.Certificates;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Reads privacy-safe dashboard projections from indexed managed-domain, scan, application, and certificate tables.</summary>
public sealed class EfManagedDomainDashboardDataSource(HipDbContext dbContext) : IManagedDomainDashboardDataSource
{
    /// <inheritdoc />
    public async Task<ManagedDomainDashboardEvidence> GetAsync(
        string domainId,
        string domainName,
        CancellationToken cancellationToken)
    {
        var domain = await dbContext.ManagedDomains.AsNoTracking()
            .SingleAsync(item => item.DomainId == domainId && item.DomainName == domainName, cancellationToken);
        var organizationName = domain.OrganizationId is null
            ? null
            : await dbContext.DomainOrganizations.AsNoTracking()
                .Where(item => item.OrganizationId == domain.OrganizationId)
                .Select(item => item.Name)
                .SingleOrDefaultAsync(cancellationToken);
        var application = await dbContext.ManagedDomainCertificateApplications.AsNoTracking()
            .Where(item => item.DomainId == domainId)
            .OrderByDescending(item => item.CreatedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);
        var certificate = await dbContext.DomainCertificates.AsNoTracking()
            .Where(item => item.IsCurrent &&
                (item.ManagedDomainId == domainId || item.ManagedDomainId == null && item.Domain == domainName))
            .OrderByDescending(item => item.IssuedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);
        var snapshot = certificate is null
            ? null
            : await dbContext.DomainCertificateSnapshots.AsNoTracking()
                .SingleOrDefaultAsync(item => item.CertificateId == certificate.CertificateId, cancellationToken);
        var scan = await dbContext.BrowserScanResults.AsNoTracking()
            .Where(item => item.Domain == domainName)
            .OrderByDescending(item => item.LastCheckedUtc)
            .FirstOrDefaultAsync(cancellationToken);

        return new ManagedDomainDashboardEvidence(
            organizationName,
            snapshot?.HipScore ?? scan?.Score,
            certificate?.Level ?? application?.RequestedLevel,
            certificate?.Status,
            certificate?.ExpiresAtUtc,
            certificate?.PublicCertificateNumber ?? certificate?.CertificateId,
            snapshot?.HttpsAvailable,
            scan?.LastCheckedUtc,
            scan?.SuspiciousLinksFound ?? 0,
            scan?.DangerousLinksFound ?? 0,
            ParseRemediation(application?.RequiredRemediationJson),
            certificate?.ExpiresAtUtc?.AddDays(-30));
    }

    private static IReadOnlyCollection<string> ParseRemediation(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            return (JsonSerializer.Deserialize<string[]>(json) ?? [])
                .Where(item => !string.IsNullOrWhiteSpace(item) && item.Length <= 500 && !item.Any(char.IsControl))
                .Take(50)
                .ToArray();
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
