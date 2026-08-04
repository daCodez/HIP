using HIP.Application.PublicLookup;

namespace HIP.Application.Dns;

/// <summary>
/// Combines a replaceable recursive DNS provider with HIP's existing public lookup service.
/// </summary>
public sealed class HipAwareDnsLookupService(
    IDnsLookupProvider dnsLookupProvider,
    IPublicDomainLookupService publicLookupService) : IHipAwareDnsLookupService
{
    /// <inheritdoc />
    public async Task<HipAwareDnsLookupResponse> LookupAsync(
        string domain,
        DnsLookupRecordType recordType,
        CancellationToken cancellationToken)
    {
        if (recordType is not DnsLookupRecordType.A and not DnsLookupRecordType.Aaaa)
        {
            throw new ArgumentException("HIP DNS currently supports A and AAAA queries only.", nameof(recordType));
        }

        var normalizedDomain = DomainInputValidator.ValidateAndNormalize(domain);
        var dnsResult = await dnsLookupProvider.LookupAsync(normalizedDomain, recordType, cancellationToken);
        var lookup = await publicLookupService.LookupDomainAsync(normalizedDomain, cancellationToken);

        return new HipAwareDnsLookupResponse(
            dnsResult.Status,
            dnsResult.IsTruncated,
            true,
            dnsResult.IsRecursionAvailable,
            false,
            false,
            [new DnsJsonQuestion($"{normalizedDomain}.", (int)recordType)],
            dnsResult.Answers
                .Select(answer => new DnsJsonAnswer(
                    answer.Name,
                    (int)answer.Type,
                    answer.TtlSeconds,
                    answer.Data))
                .ToArray(),
            dnsLookupProvider.Name,
            new HipDnsTrustSummary(
                lookup.Domain,
                lookup.DisplayScore,
                lookup.Status.ToString(),
                lookup.RiskLevel,
                lookup.VerificationStatus,
                lookup.EvidenceCoverage,
                lookup.EvidenceConfidence,
                lookup.RecommendedAction,
                lookup.LastCheckedUtc,
                lookup.PublicLookupUrl,
                lookup.DataSource,
                false));
    }
}
