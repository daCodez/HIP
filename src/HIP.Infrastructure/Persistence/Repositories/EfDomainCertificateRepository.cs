using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;
using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Insert-only EF repository for signed domain certificates and their issuance audit events.</summary>
public sealed class EfDomainCertificateRepository(
    HipDbContext dbContext,
    ICanonicalJsonService canonicalJsonService) : IDomainCertificateRepository, IDomainCertificateOwnerQuery, IDomainEnrollmentRepository
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
    public async Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(
        DomainEnrollmentStartRecord enrollment,
        CancellationToken cancellationToken)
    {
        ValidateEnrollmentStart(enrollment);
        var collision = await FindEnrollmentCollisionAsync(enrollment, cancellationToken);
        if (collision is not null)
        {
            return collision;
        }

        dbContext.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = enrollment.EnrollmentId,
            OwnerId = enrollment.OwnerId,
            Domain = enrollment.Domain,
            Status = enrollment.Status,
            PolicyVersion = enrollment.PolicyVersion,
            IsCurrent = true,
            CreatedAtUtc = enrollment.CreatedAtUtc,
            UpdatedAtUtc = enrollment.CreatedAtUtc,
            AggregateVersion = 1
        });
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = enrollment.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = null,
            EventType = "EnrollmentStarted",
            PreviousStatus = DomainEnrollmentStatus.Draft.ToString(),
            CurrentStatus = enrollment.Status.ToString(),
            ActorId = enrollment.OwnerId,
            PublicSummary = "Domain enrollment started; domain control is not yet verified.",
            PolicyVersion = enrollment.PolicyVersion,
            OccurredAtUtc = enrollment.CreatedAtUtc
        });

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return new DomainEnrollmentRepositoryWriteResult(
                DomainEnrollmentRepositoryWriteStatus.Created,
                enrollment);
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            var reconciled = await FindEnrollmentCollisionAsync(enrollment, cancellationToken);
            if (reconciled is null)
            {
                throw;
            }

            return reconciled;
        }
    }

    private async Task<DomainEnrollmentRepositoryWriteResult?> FindEnrollmentCollisionAsync(
        DomainEnrollmentStartRecord candidate,
        CancellationToken cancellationToken)
    {
        var existing = await dbContext.DomainEnrollments.AsNoTracking()
            .SingleOrDefaultAsync(
                item => item.EnrollmentId == candidate.EnrollmentId || item.Domain == candidate.Domain && item.IsCurrent,
                cancellationToken);
        if (existing is null)
        {
            return null;
        }

        var exactAudit = await dbContext.DomainCertificateEvents.AsNoTracking().AnyAsync(
            item => item.EventId == candidate.AuditEventId &&
                    item.EnrollmentId == existing.EnrollmentId &&
                    item.EventType == "EnrollmentStarted",
            cancellationToken);
        var exact = existing.EnrollmentId == candidate.EnrollmentId &&
                    existing.OwnerId == candidate.OwnerId &&
                    existing.Domain == candidate.Domain &&
                    existing.Status == candidate.Status &&
                    existing.PolicyVersion == candidate.PolicyVersion &&
                    exactAudit;
        return new DomainEnrollmentRepositoryWriteResult(
            exact
                ? DomainEnrollmentRepositoryWriteStatus.ExistingSame
                : DomainEnrollmentRepositoryWriteStatus.Conflict,
            exact ? candidate : null);
    }

    private static void ValidateEnrollmentStart(DomainEnrollmentStartRecord enrollment)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        ValidateIdentifier(enrollment.EnrollmentId, 128);
        ValidateIdentifier(enrollment.OwnerId, 256);
        ValidateIdentifier(enrollment.AuditEventId, 128);
        ValidateIdentifier(enrollment.PolicyVersion, 128);
        var domain = HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(enrollment.Domain);
        if (domain != enrollment.Domain ||
            enrollment.Status != DomainEnrollmentStatus.PendingOwnership ||
            enrollment.CreatedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Initial domain enrollment state is invalid.", nameof(enrollment));
        }
    }

    /// <inheritdoc />
    public async Task<DomainEnrollmentTransitionWriteResult> TryApplyOwnershipVerificationAsync(
        DomainOwnershipVerificationRecord verification,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verification);
        ValidateIdentifier(verification.EnrollmentId, 128);
        ValidateIdentifier(verification.OwnerId, 256);
        ValidateIdentifier(verification.AuditEventId, 128);
        var domain = HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(verification.Domain);
        if (domain != verification.Domain ||
            verification.Method != HIP.Domain.Identity.VerificationMethod.DnsTxt ||
            verification.VerifiedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Domain ownership verification state is invalid.", nameof(verification));
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == verification.EnrollmentId &&
                    item.OwnerId == verification.OwnerId &&
                    item.Domain == verification.Domain &&
                    item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.NotFound);
        }
        if (enrollment.Status != DomainEnrollmentStatus.PendingOwnership)
        {
            return new DomainEnrollmentTransitionWriteResult(
                enrollment.DnsVerifiedAtUtc is not null &&
                enrollment.Status is not DomainEnrollmentStatus.Draft and not DomainEnrollmentStatus.PendingOwnership
                    ? DomainEnrollmentTransitionWriteStatus.AlreadyApplied
                    : DomainEnrollmentTransitionWriteStatus.Conflict);
        }
        if (await dbContext.DomainCertificateEvents.AnyAsync(
                item => item.EventId == verification.AuditEventId,
                cancellationToken))
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.Conflict);
        }

        DomainEnrollmentLifecycle.RequireTransition(
            enrollment.Status,
            DomainEnrollmentStatus.OwnershipVerified);
        var previous = enrollment.Status;
        enrollment.Status = DomainEnrollmentStatus.OwnershipVerified;
        enrollment.DnsVerifiedAtUtc = verification.VerifiedAtUtc;
        enrollment.UpdatedAtUtc = verification.VerifiedAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = verification.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = null,
            EventType = "DomainOwnershipVerified",
            PreviousStatus = previous.ToString(),
            CurrentStatus = enrollment.Status.ToString(),
            ActorId = verification.OwnerId,
            PublicSummary = "HIP verified domain control through DNS.",
            PolicyVersion = enrollment.PolicyVersion,
            OccurredAtUtc = verification.VerifiedAtUtc
        });
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.Updated);
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.Conflict);
        }
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
