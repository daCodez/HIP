using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Protocol;

namespace HIP.Application.Certificates;

/// <summary>Immutable evidence captured at certificate issuance or renewal time.</summary>
public sealed record DomainCertificateIssuanceSnapshot(
    int HipScore,
    int? DomainTrustScore,
    int? PageTrustScore,
    int? ContentRiskScore,
    string RelevantSecurityStatus,
    bool HttpsAvailable,
    HIP.Domain.Domains.DomainDnssecStatus DnssecStatus,
    string? ScanId,
    string RuleVersion,
    string PolicyVersion,
    DateTimeOffset EvaluatedAtUtc);

/// <summary>Authorized application request to issue one policy-evaluated domain certificate.</summary>
public sealed record DomainCertificateIssuanceRequest(
    string EnrollmentId,
    string OwnerId,
    string ActorId,
    DomainCertificateSigningDraft Draft,
    string? ManagedDomainId = null,
    string? OrganizationId = null,
    string? ApplicationId = null,
    string? PublicCertificateNumber = null,
    DomainCertificateIssuanceSnapshot? Snapshot = null);

/// <summary>Safe outcome returned by the transactional certificate issuance coordinator.</summary>
public enum DomainCertificateIssuanceStatus
{
    InvalidRequest,
    Ineligible,
    ReviewRequired,
    SignerUnavailable,
    SignerNotAuthorized,
    VerificationFailed,
    PersistenceUnavailable,
    Conflict,
    Issued,
    Existing
}

/// <summary>Issuance result containing a certificate only after a durable or idempotent write.</summary>
public sealed record DomainCertificateIssuanceResult(
    DomainCertificateIssuanceStatus Status,
    SignedDomainTrustCertificate? Certificate = null);

/// <summary>Coordinates idempotent signing and atomic certificate/audit persistence.</summary>
public interface IDomainCertificateIssuanceService
{
    /// <summary>Issues or returns the exact existing certificate for an authorized request.</summary>
    Task<DomainCertificateIssuanceResult> IssueAsync(
        DomainCertificateIssuanceRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Turns an eligible certificate decision into one durable, audited signed certificate.</summary>
public sealed class DomainCertificateIssuanceService(
    IDomainCertificateSigningService signingService,
    IDomainCertificateRepository certificateRepository,
    ICanonicalJsonService canonicalJsonService) : IDomainCertificateIssuanceService
{
    private static readonly JsonSerializerOptions SourceJsonOptions = CreateJsonOptions();
    private readonly IDomainCertificateSigningService signer =
        signingService ?? throw new ArgumentNullException(nameof(signingService));
    private readonly IDomainCertificateRepository repository =
        certificateRepository ?? throw new ArgumentNullException(nameof(certificateRepository));
    private readonly ICanonicalJsonService canonicalizer =
        canonicalJsonService ?? throw new ArgumentNullException(nameof(canonicalJsonService));

    /// <inheritdoc />
    public async Task<DomainCertificateIssuanceResult> IssueAsync(
        DomainCertificateIssuanceRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string sourceDecisionDigest;
        try
        {
            Validate(request);
            sourceDecisionDigest = SourceDecisionDigest(request.Draft, canonicalizer);
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or NullReferenceException)
        {
            return Result(DomainCertificateIssuanceStatus.InvalidRequest);
        }

        HipStoredDomainCertificate? existing;
        try
        {
            existing = await repository.GetByIdAsync(
                    request.Draft.CertificateId,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateIssuanceStatus.PersistenceUnavailable);
        }

        if (existing is not null)
        {
            return SameIssuance(existing, request, sourceDecisionDigest)
                ? new DomainCertificateIssuanceResult(
                    DomainCertificateIssuanceStatus.Existing,
                    existing.Certificate)
                : Result(DomainCertificateIssuanceStatus.Conflict);
        }

        DomainCertificateSigningResult signing;
        try
        {
            signing = await signer.SignAsync(request.Draft, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateIssuanceStatus.SignerUnavailable);
        }

        if (signing.Status != DomainCertificateSigningStatus.Signed || signing.Certificate is null)
        {
            return Result(Map(signing.Status));
        }

        var stored = CreateStored(request, signing.Certificate, canonicalizer);

        DomainCertificateRepositoryWriteResult write;
        try
        {
            write = await repository.TryCreateIssuedAsync(stored, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateIssuanceStatus.PersistenceUnavailable);
        }

        return write.Status switch
        {
            DomainCertificateRepositoryWriteStatus.Created =>
                new DomainCertificateIssuanceResult(
                    DomainCertificateIssuanceStatus.Issued,
                    write.StoredCertificate?.Certificate ?? signing.Certificate),
            DomainCertificateRepositoryWriteStatus.ExistingSame
                when write.StoredCertificate is not null =>
                new DomainCertificateIssuanceResult(
                    DomainCertificateIssuanceStatus.Existing,
                    write.StoredCertificate.Certificate),
            DomainCertificateRepositoryWriteStatus.Conflict =>
                Result(DomainCertificateIssuanceStatus.Conflict),
            _ => Result(DomainCertificateIssuanceStatus.PersistenceUnavailable)
        };
    }

    internal static HipStoredDomainCertificate CreateStored(
        DomainCertificateIssuanceRequest request,
        SignedDomainTrustCertificate certificate,
        ICanonicalJsonService canonicalizer)
    {
        Validate(request);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(canonicalizer);
        var sourceDecisionDigest = SourceDecisionDigest(request.Draft, canonicalizer);
        var certificateJson = DomainTrustCertificateJson.Serialize(certificate);
        var certificateDigest = Digest(Encoding.UTF8.GetBytes(certificateJson), canonicalizer);
        var auditEvent = new DomainCertificateAuditEvent(
            EventId(certificate.Payload.CertificateId, sourceDecisionDigest),
            request.ActorId,
            "CertificateIssued",
            null,
            HIP.Domain.Certificates.DomainCertificateStatus.Active,
            null,
            request.Draft.Evaluation.PublicMeaning,
            certificate.Payload.IssuedAtUtc);
        return new HipStoredDomainCertificate(
            request.EnrollmentId, request.OwnerId, certificate, certificateJson,
            certificateDigest, sourceDecisionDigest, auditEvent,
            ManagedDomainId: request.ManagedDomainId,
            OrganizationId: request.OrganizationId,
            ApplicationId: request.ApplicationId,
            PublicCertificateNumber: request.PublicCertificateNumber,
            Snapshot: request.Snapshot);
    }

    private static string SourceDecisionDigest(
        DomainCertificateSigningDraft draft,
        ICanonicalJsonService canonicalizer)
    {
        var evaluation = draft.Evaluation;
        var identity = new IssuanceIdentity(
            draft.CertificateId,
            draft.CertificateVersion,
            draft.Domain,
            draft.Level,
            draft.PublicDisplayName,
            draft.PublicOrganizationName,
            draft.RegistrantPublicKeyId,
            draft.CompletedVerificationMethods.Distinct().Order().ToArray(),
            draft.PublicRiskClassification,
            draft.PublicFindingCodes.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            draft.RevocationStatusUrl,
            draft.PublicCertificateUrl,
            draft.LastVerificationAtUtc,
            draft.LastMonitoringAtUtc,
            evaluation.Domain,
            evaluation.RequestedLevel,
            evaluation.PolicyVersion,
            evaluation.Decision,
            evaluation.PublicMeaning,
            evaluation.Requirements
                .OrderBy(item => item.Code, StringComparer.Ordinal)
                .ThenBy(item => item.Status)
                .ThenBy(item => item.PublicSummary, StringComparer.Ordinal)
                .ToArray(),
            evaluation.EvaluatedAtUtc);
        return Digest(JsonSerializer.SerializeToUtf8Bytes(identity, SourceJsonOptions), canonicalizer);
    }

    private static string Digest(
        ReadOnlySpan<byte> json,
        ICanonicalJsonService canonicalizer) =>
        $"sha256:{Convert.ToHexString(
            SHA256.HashData(canonicalizer.Canonicalize(json))).ToLowerInvariant()}";

    private static bool SameIssuance(
        HipStoredDomainCertificate existing,
        DomainCertificateIssuanceRequest request,
        string sourceDecisionDigest) =>
        existing.EnrollmentId == request.EnrollmentId &&
        existing.OwnerId == request.OwnerId &&
        existing.Certificate.Payload.CertificateId == request.Draft.CertificateId &&
        existing.Certificate.Payload.Domain == request.Draft.Domain &&
        existing.Certificate.Payload.Level == request.Draft.Level &&
        existing.Certificate.Payload.CertificateVersion == request.Draft.CertificateVersion &&
        existing.SourceDecisionDigest == sourceDecisionDigest &&
        existing.ManagedDomainId == request.ManagedDomainId &&
        existing.OrganizationId == request.OrganizationId &&
        existing.ApplicationId == request.ApplicationId &&
        existing.PublicCertificateNumber == request.PublicCertificateNumber &&
        Equals(existing.Snapshot, request.Snapshot);

    private static void Validate(DomainCertificateIssuanceRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Draft);
        ArgumentNullException.ThrowIfNull(request.Draft.Evaluation);
        ArgumentNullException.ThrowIfNull(request.Draft.CompletedVerificationMethods);
        ArgumentNullException.ThrowIfNull(request.Draft.PublicFindingCodes);
        ArgumentNullException.ThrowIfNull(request.Draft.Evaluation.Requirements);
        ValidateIdentifier(request.EnrollmentId, 128);
        ValidateIdentifier(request.OwnerId, 256);
        ValidateIdentifier(request.ActorId, 256);
        ValidateOptionalIdentifier(request.ManagedDomainId, 256);
        ValidateOptionalIdentifier(request.OrganizationId, 256);
        ValidateOptionalIdentifier(request.ApplicationId, 128);
        ValidateOptionalIdentifier(request.PublicCertificateNumber, 64);
        if (request.Snapshot is { } snapshot)
        {
            ValidateSnapshot(snapshot, request.Draft.Evaluation.PolicyVersion);
        }
    }

    private static void ValidateIdentifier(string value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximumLength ||
            value.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException("Certificate issuance identifier is invalid.");
        }
    }

    private static void ValidateOptionalIdentifier(string? value, int maximumLength)
    {
        if (value is not null) ValidateIdentifier(value, maximumLength);
    }

    private static void ValidateSnapshot(DomainCertificateIssuanceSnapshot snapshot, string evaluationPolicyVersion)
    {
        if (snapshot.HipScore is < 0 or > 100 ||
            snapshot.DomainTrustScore is < 0 or > 100 || snapshot.PageTrustScore is < 0 or > 100 ||
            snapshot.ContentRiskScore is < 0 or > 100 || snapshot.EvaluatedAtUtc.Offset != TimeSpan.Zero ||
            string.IsNullOrWhiteSpace(snapshot.RelevantSecurityStatus) || snapshot.RelevantSecurityStatus.Length > 80 ||
            string.IsNullOrWhiteSpace(snapshot.RuleVersion) || snapshot.RuleVersion.Length > 128 ||
            string.IsNullOrWhiteSpace(snapshot.PolicyVersion) || snapshot.PolicyVersion.Length > 128 ||
            snapshot.RelevantSecurityStatus.Any(char.IsControl) || snapshot.RuleVersion.Any(char.IsControl) ||
            snapshot.PolicyVersion.Any(char.IsControl) || snapshot.ScanId?.Any(char.IsControl) == true ||
            !string.Equals(snapshot.PolicyVersion, evaluationPolicyVersion, StringComparison.Ordinal) ||
            snapshot.ScanId is { Length: > 220 })
        {
            throw new ArgumentException("Certificate issuance snapshot is invalid.");
        }
    }

    private static string EventId(string certificateId, string sourceDecisionDigest)
    {
        var material = Encoding.UTF8.GetBytes($"{certificateId}\n{sourceDecisionDigest}");
        return $"certificate-event:{Convert.ToHexString(SHA256.HashData(material)).ToLowerInvariant()}";
    }

    private static DomainCertificateIssuanceStatus Map(DomainCertificateSigningStatus status) => status switch
    {
        DomainCertificateSigningStatus.InvalidRequest => DomainCertificateIssuanceStatus.InvalidRequest,
        DomainCertificateSigningStatus.Ineligible => DomainCertificateIssuanceStatus.Ineligible,
        DomainCertificateSigningStatus.ReviewRequired => DomainCertificateIssuanceStatus.ReviewRequired,
        DomainCertificateSigningStatus.SignerUnavailable => DomainCertificateIssuanceStatus.SignerUnavailable,
        DomainCertificateSigningStatus.SignerNotAuthorized => DomainCertificateIssuanceStatus.SignerNotAuthorized,
        DomainCertificateSigningStatus.VerificationFailed => DomainCertificateIssuanceStatus.VerificationFailed,
        _ => DomainCertificateIssuanceStatus.InvalidRequest
    };

    private static DomainCertificateIssuanceResult Result(DomainCertificateIssuanceStatus status) =>
        new(status);

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private sealed record IssuanceIdentity(
        string CertificateId,
        int CertificateVersion,
        string Domain,
        HIP.Domain.Certificates.DomainCertificateLevel Level,
        string? PublicDisplayName,
        string? PublicOrganizationName,
        string? RegistrantPublicKeyId,
        IReadOnlyCollection<HIP.Domain.Identity.VerificationMethod> CompletedVerificationMethods,
        DomainCertificatePublicRiskClassification PublicRiskClassification,
        IReadOnlyCollection<string> PublicFindingCodes,
        string RevocationStatusUrl,
        string PublicCertificateUrl,
        DateTimeOffset LastVerificationAtUtc,
        DateTimeOffset? LastMonitoringAtUtc,
        string EvaluationDomain,
        HIP.Domain.Certificates.DomainCertificateLevel EvaluationLevel,
        string PolicyVersion,
        DomainCertificatePolicyDecision Decision,
        string PublicMeaning,
        IReadOnlyCollection<DomainCertificateRequirementResult> Requirements,
        DateTimeOffset EvaluatedAtUtc);
}
