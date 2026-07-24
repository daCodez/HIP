using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Insert-only EF repository for signed domain certificates and their issuance audit events.</summary>
public sealed class EfDomainCertificateRepository(
    HipDbContext dbContext,
    ICanonicalJsonService canonicalJsonService) : IDomainCertificateRepository, IDomainCertificateOwnerQuery
{
    private static readonly JsonSerializerOptions CollectionJsonOptions = CreateCollectionOptions();
    private readonly ICanonicalJsonService canonicalizer =
        canonicalJsonService ?? throw new ArgumentNullException(nameof(canonicalJsonService));

    /// <inheritdoc />
    public async Task<HipStoredDomainCertificate?> GetByIdAsync(
        string certificateId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateId);
        var entity = await dbContext.DomainCertificates.AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.CertificateId == certificateId &&
                        item.SignedCertificateJson != null,
                cancellationToken);
        return entity is null ? null : await FromEntityAsync(entity, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<HipStoredDomainCertificate?> GetCurrentByDomainAsync(
        string domain,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        var entity = await dbContext.DomainCertificates.AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.Domain == domain &&
                        item.IsCurrent &&
                        item.SignedCertificateJson != null,
                cancellationToken);
        return entity is null ? null : await FromEntityAsync(entity, cancellationToken);
    }
    /// <inheritdoc />
    public async Task<IReadOnlyList<OwnerDomainCertificateSummary>> ListForOwnerAsync(
        string ownerId,
        int offset,
        int limit,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(ownerId, 256);
        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }
        if (limit is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        var enrollments = dbContext.DomainEnrollments.AsNoTracking()
            .Where(item => item.OwnerId == ownerId && item.IsCurrent)
            .OrderBy(item => item.Domain)
            .Skip(offset)
            .Take(limit);
        var currentCertificates = dbContext.DomainCertificates.AsNoTracking()
            .Where(item => item.IsCurrent);
        return await (
                from enrollment in enrollments
                join certificate in currentCertificates
                    on enrollment.EnrollmentId equals certificate.EnrollmentId into certificates
                from certificate in certificates.DefaultIfEmpty()
                select new OwnerDomainCertificateSummary(
                    enrollment.EnrollmentId,
                    enrollment.Domain,
                    enrollment.Status,
                    enrollment.PolicyVersion,
                    enrollment.CreatedAtUtc,
                    enrollment.UpdatedAtUtc,
                    enrollment.DnsVerifiedAtUtc,
                    enrollment.WebsiteVerifiedAtUtc,
                    enrollment.IdentityCompletedAtUtc,
                    enrollment.SecurityReviewCompletedAtUtc,
                    enrollment.LastMonitoringAtUtc,
                    enrollment.CurrentScore,
                    enrollment.UnresolvedCriticalFindings,
                    certificate == null ? null : certificate.CertificateId,
                    certificate == null ? null : certificate.Status,
                    certificate == null ? null : certificate.Level,
                    certificate == null ? null : certificate.IssuedAtUtc,
                    certificate == null ? null : certificate.ExpiresAtUtc,
                    certificate == null ? null : certificate.LastVerificationAtUtc))
            .ToListAsync(cancellationToken);
    }


    /// <inheritdoc />
    public async Task<DomainCertificateRepositoryWriteResult> TryCreateIssuedAsync(
        HipStoredDomainCertificate certificate,
        CancellationToken cancellationToken)
    {
        Validate(certificate, requireInitialActiveStatus: true);
        var existing = await FindCollisionAsync(certificate, cancellationToken);
        if (existing is not null)
        {
            return Collision(existing, certificate);
        }

        dbContext.DomainCertificates.Add(ToCertificateEntity(certificate));
        dbContext.DomainCertificateEvents.Add(ToEventEntity(certificate));
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return new DomainCertificateRepositoryWriteResult(
                DomainCertificateRepositoryWriteStatus.Created,
                certificate);
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            existing = await FindCollisionAsync(certificate, cancellationToken);
            if (existing is null)
            {
                throw;
            }

            return Collision(existing, certificate);
        }
    }

    private async Task<HipStoredDomainCertificate?> FindCollisionAsync(
        HipStoredDomainCertificate candidate,
        CancellationToken cancellationToken)
    {
        var certificateId = candidate.Certificate.Payload.CertificateId;
        var domain = candidate.Certificate.Payload.Domain;
        var entity = await dbContext.DomainCertificates.AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.CertificateId == certificateId || item.Domain == domain && item.IsCurrent,
                cancellationToken);
        return entity is null ? null : await FromEntityAsync(entity, cancellationToken);
    }

    private async Task<HipStoredDomainCertificate> FromEntityAsync(
        HipDomainCertificateEntity entity,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(entity.SignedCertificateJson))
        {
            throw new InvalidOperationException("Stored domain certificate has no signed public document.");
        }

        var certificate = DomainTrustCertificateJson.Deserialize(entity.SignedCertificateJson);
        var auditEvent = await dbContext.DomainCertificateEvents.AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.CertificateId == entity.CertificateId &&
                        item.EventType == "CertificateIssued",
                cancellationToken)
            ?? throw new InvalidOperationException("Stored domain certificate has no issuance audit event.");
        var stored = new HipStoredDomainCertificate(
            entity.EnrollmentId,
            entity.OwnerId,
            certificate,
            entity.SignedCertificateJson,
            Required(entity.CertificateDigest, "certificate digest"),
            Required(entity.SourceDecisionDigest, "source decision digest"),
            new DomainCertificateAuditEvent(
                auditEvent.EventId,
                auditEvent.ActorId,
                auditEvent.EventType,
                ParseStatus(auditEvent.PreviousStatus),
                Enum.Parse<HIP.Domain.Certificates.DomainCertificateStatus>(
                    auditEvent.CurrentStatus,
                    ignoreCase: false),
                auditEvent.ReasonCode,
                auditEvent.PublicSummary,
                auditEvent.OccurredAtUtc),
            entity.Status);
        Validate(stored, requireInitialActiveStatus: false);
        ValidateIndexes(entity, stored);
        return stored;
    }

    private HipDomainCertificateEntity ToCertificateEntity(HipStoredDomainCertificate stored)
    {
        var certificate = stored.Certificate;
        var payload = certificate.Payload;
        return new HipDomainCertificateEntity
        {
            CertificateId = payload.CertificateId,
            EnrollmentId = stored.EnrollmentId,
            OwnerId = stored.OwnerId,
            Domain = payload.Domain,
            Level = payload.Level,
            Status = stored.CurrentStatus,
            PolicyVersion = payload.PolicyVersion,
            CertificateVersion = payload.CertificateVersion,
            IsCurrent = true,
            IssuedAtUtc = payload.IssuedAtUtc,
            ExpiresAtUtc = payload.ExpiresAtUtc,
            LastVerificationAtUtc = payload.LastVerificationAtUtc,
            LastMonitoringAtUtc = payload.LastMonitoringAtUtc,
            PublicDisplayName = payload.PublicDisplayName,
            PublicOrganizationName = payload.PublicOrganizationName,
            RegistrantPublicKeyId = payload.RegistrantPublicKeyId,
            SigningAuthorityId = certificate.Signature.AuthorityId,
            SigningKeyId = certificate.Signature.KeyId,
            SignatureAlgorithm = certificate.Signature.Algorithm,
            SignatureAlgorithmFamily = certificate.Signature.AlgorithmFamily.ToString(),
            SignatureCanonicalization = certificate.Signature.Canonicalization,
            CanonicalPayload = Encoding.UTF8.GetString(
                canonicalizer.Canonicalize(DomainTrustCertificateJson.SigningPayload(payload))),
            Signature = certificate.Signature.Value,
            SignedCertificateJson = stored.SignedCertificateJson,
            CertificateDigest = stored.CertificateDigest,
            SourceDecisionDigest = stored.SourceDecisionDigest,
            VerificationMethodsJson = JsonSerializer.Serialize(
                payload.CompletedVerificationMethods,
                CollectionJsonOptions),
            PublicFindingsSummaryJson = JsonSerializer.Serialize(
                payload.PublicFindingCodes,
                CollectionJsonOptions),
            PublicRiskClassification = payload.PublicRiskClassification.ToString(),
            PublicCertificateUrl = payload.PublicCertificateUrl,
            RevocationStatusUrl = payload.RevocationStatusUrl,
            AggregateVersion = 1
        };
    }

    private static HipDomainCertificateEventEntity ToEventEntity(HipStoredDomainCertificate stored) => new()
    {
        EventId = stored.IssuanceEvent.EventId,
        EnrollmentId = stored.EnrollmentId,
        CertificateId = stored.Certificate.Payload.CertificateId,
        EventType = stored.IssuanceEvent.EventType,
        PreviousStatus = stored.IssuanceEvent.PreviousStatus?.ToString(),
        CurrentStatus = stored.IssuanceEvent.CurrentStatus.ToString(),
        ActorId = stored.IssuanceEvent.ActorId,
        ReasonCode = stored.IssuanceEvent.ReasonCode,
        PublicSummary = stored.IssuanceEvent.PublicSummary,
        PolicyVersion = stored.Certificate.Payload.PolicyVersion,
        EvidenceDigest = stored.SourceDecisionDigest,
        OccurredAtUtc = stored.IssuanceEvent.OccurredAtUtc
    };

    private void Validate(
        HipStoredDomainCertificate stored,
        bool requireInitialActiveStatus)
    {
        ArgumentNullException.ThrowIfNull(stored);
        ArgumentNullException.ThrowIfNull(stored.Certificate);
        ArgumentNullException.ThrowIfNull(stored.IssuanceEvent);
        var expectedJson = DomainTrustCertificateJson.Serialize(stored.Certificate);
        if (!string.Equals(stored.SignedCertificateJson, expectedJson, StringComparison.Ordinal) ||
            !string.Equals(stored.CertificateDigest, Digest(expectedJson), StringComparison.Ordinal) ||
            !IsDigest(stored.SourceDecisionDigest) ||
            stored.IssuanceEvent.EventType != "CertificateIssued" ||
            stored.IssuanceEvent.PreviousStatus is not null ||
            stored.IssuanceEvent.CurrentStatus != HIP.Domain.Certificates.DomainCertificateStatus.Active ||
            stored.IssuanceEvent.OccurredAtUtc != stored.Certificate.Payload.IssuedAtUtc)
        {
            throw new ArgumentException("Stored domain certificate issuance data is inconsistent.", nameof(stored));
        }

        ValidateIdentifier(stored.EnrollmentId, 128);
        ValidateIdentifier(stored.OwnerId, 256);
        ValidateIdentifier(stored.IssuanceEvent.EventId, 128);
        ValidateIdentifier(stored.IssuanceEvent.ActorId, 256);
        if (requireInitialActiveStatus &&
            (stored.Certificate.Payload.Status != HIP.Domain.Certificates.DomainCertificateStatus.Active ||
             stored.CurrentStatus != HIP.Domain.Certificates.DomainCertificateStatus.Active))
        {
            throw new ArgumentException("New domain certificate issuance must start active.", nameof(stored));
        }
    }

    private void ValidateIndexes(
        HipDomainCertificateEntity entity,
        HipStoredDomainCertificate stored)
    {
        var payload = stored.Certificate.Payload;
        var signature = stored.Certificate.Signature;
        if (entity.CertificateId != payload.CertificateId ||
            entity.EnrollmentId != stored.EnrollmentId ||
            entity.OwnerId != stored.OwnerId ||
            entity.Domain != payload.Domain ||
            entity.Level != payload.Level ||
            entity.Status != stored.CurrentStatus ||
            entity.PolicyVersion != payload.PolicyVersion ||
            entity.CertificateVersion != payload.CertificateVersion ||
            entity.IssuedAtUtc != payload.IssuedAtUtc ||
            entity.ExpiresAtUtc != payload.ExpiresAtUtc ||
            entity.LastVerificationAtUtc != payload.LastVerificationAtUtc ||
            entity.LastMonitoringAtUtc != payload.LastMonitoringAtUtc ||
            entity.PublicDisplayName != payload.PublicDisplayName ||
            entity.PublicOrganizationName != payload.PublicOrganizationName ||
            entity.RegistrantPublicKeyId != payload.RegistrantPublicKeyId ||
            entity.SigningAuthorityId != signature.AuthorityId ||
            entity.SigningKeyId != signature.KeyId ||
            entity.SignatureAlgorithm != signature.Algorithm ||
            entity.SignatureAlgorithmFamily != signature.AlgorithmFamily.ToString() ||
            entity.SignatureCanonicalization != signature.Canonicalization ||
            entity.Signature != signature.Value ||
            entity.PublicRiskClassification != payload.PublicRiskClassification.ToString() ||
            entity.PublicCertificateUrl != payload.PublicCertificateUrl ||
            entity.RevocationStatusUrl != payload.RevocationStatusUrl)
        {
            throw new InvalidOperationException(
                "Stored domain certificate indexes do not match the signed certificate.");
        }
    }

    private static DomainCertificateRepositoryWriteResult Collision(
        HipStoredDomainCertificate existing,
        HipStoredDomainCertificate candidate) => new(
        existing.EnrollmentId == candidate.EnrollmentId &&
        existing.OwnerId == candidate.OwnerId &&
        existing.Certificate.Payload.CertificateId == candidate.Certificate.Payload.CertificateId &&
        existing.SourceDecisionDigest == candidate.SourceDecisionDigest &&
        existing.SignedCertificateJson == candidate.SignedCertificateJson &&
        existing.CertificateDigest == candidate.CertificateDigest
            ? DomainCertificateRepositoryWriteStatus.ExistingSame
            : DomainCertificateRepositoryWriteStatus.Conflict,
        existing);

    private string Digest(string value) =>
        $"sha256:{Convert.ToHexString(SHA256.HashData(
            canonicalizer.Canonicalize(Encoding.UTF8.GetBytes(value)))).ToLowerInvariant()}";

    private static bool IsDigest(string value) =>
        value.Length == 71 &&
        value.StartsWith("sha256:", StringComparison.Ordinal) &&
        value.AsSpan(7).IndexOfAnyExcept("0123456789abcdef") < 0;

    private static void ValidateIdentifier(string value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximumLength ||
            value.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException("Certificate repository identifier is invalid.");
        }
    }

    private static string Required(string? value, string fieldName) =>
        !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException($"Stored domain certificate is missing its {fieldName}.");

    private static HIP.Domain.Certificates.DomainCertificateStatus? ParseStatus(string? value) =>
        value is null
            ? null
            : Enum.Parse<HIP.Domain.Certificates.DomainCertificateStatus>(value, ignoreCase: false);

    private static JsonSerializerOptions CreateCollectionOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
