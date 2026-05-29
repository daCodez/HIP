namespace HIP.Domain.Reporting;

public sealed record PrivacySafeEvidence(
    string EvidenceType,
    string Summary,
    IReadOnlyDictionary<string, string> Facts,
    bool ContainsPrivateContent = false);
