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
    ICanonicalJsonService canonicalJsonService) : IDomainCertificateRepository, IDomainCertificateOwnerQuery, IDomainEnrollmentRepository, IDomainCertificateAdminQuery, IDomainCertificateLifecycleRepository, IDomainCertificateMonitoringRepository, IDomainCertificateMonitoringScheduleRepository
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
    public async Task<DomainEnrollmentStateRecord?> GetCurrentAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(ownerId, 256);
        var normalized = HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(domain);
        return await dbContext.DomainEnrollments.AsNoTracking()
            .Where(item => item.OwnerId == ownerId && item.Domain == normalized && item.IsCurrent)
            .Select(item => new DomainEnrollmentStateRecord(
                item.EnrollmentId,
                item.OwnerId,
                item.Domain,
                item.Status,
                item.DnsVerifiedAtUtc,
                item.WebsiteVerifiedAtUtc,
                item.IdentityCompletedAtUtc,
                item.PublicDisplayName,
                item.PublicOrganizationName,
                item.SecurityReviewCompletedAtUtc,
                item.CurrentScore,
                item.UnresolvedCriticalFindings,
                item.ApplicationStatus,
                item.ApplicationSubmittedAtUtc,
                item.ApplicationReviewedAtUtc,
                item.ApplicantAttestationDigest))
            .SingleOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<DomainMonitoringEnrollmentState?> GetForMonitoringAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(ownerId, 256);
        var normalized = HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(domain);
        return await (
                from enrollment in dbContext.DomainEnrollments.AsNoTracking()
                    .Where(item => item.OwnerId == ownerId && item.Domain == normalized && item.IsCurrent)
                join certificate in dbContext.DomainCertificates.AsNoTracking().Where(item => item.IsCurrent)
                    on enrollment.EnrollmentId equals certificate.EnrollmentId
                select new DomainMonitoringEnrollmentState(
                    enrollment.EnrollmentId,
                    enrollment.OwnerId,
                    enrollment.Domain,
                    enrollment.Status,
                    certificate.Status,
                    certificate.Level,
                    enrollment.DnsVerifiedAtUtc,
                    enrollment.WebsiteVerifiedAtUtc,
                    enrollment.IdentityCompletedAtUtc,
                    enrollment.MonitoringEnabledAtUtc,
                    enrollment.LastMonitoringAtUtc,
                    enrollment.CurrentScore,
                    enrollment.MonitoringNextCheckAtUtc,
                    enrollment.MonitoringFailureCount))
            .SingleOrDefaultAsync(cancellationToken);
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
                    certificate == null ? null : certificate.LastVerificationAtUtc,
                    enrollment.ApplicationStatus,
                    enrollment.ApplicationSubmittedAtUtc,
                    enrollment.ApplicationReviewedAtUtc,
                    enrollment.ApplicantAttestationDigest,
                    enrollment.MonitoringEnabledAtUtc,
                    enrollment.MonitoringNextCheckAtUtc,
                    enrollment.MonitoringFailureCount))
            .ToListAsync(cancellationToken);
    }
    /// <inheritdoc />
    public async Task<IReadOnlyList<AdminDomainCertificateSummary>> ListForAdminAsync(
        int offset,
        int limit,
        CancellationToken cancellationToken)
    {
        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }
        if (limit is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        var enrollments = dbContext.DomainEnrollments.AsNoTracking()
            .Where(item => item.IsCurrent)
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
                select new AdminDomainCertificateSummary(
                    enrollment.EnrollmentId,
                    enrollment.Domain,
                    enrollment.Status,
                    enrollment.PolicyVersion,
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
                    certificate == null ? null : certificate.LastVerificationAtUtc,
                    enrollment.ApplicationStatus,
                    enrollment.ApplicationSubmittedAtUtc,
                    enrollment.ApplicationReviewedAtUtc,
                    enrollment.ApplicantAttestationDigest,
                    enrollment.MonitoringEnabledAtUtc,
                    enrollment.MonitoringNextCheckAtUtc,
                    enrollment.MonitoringFailureCount))
            .ToListAsync(cancellationToken);
    }


    /// <inheritdoc />
    public async Task<PublicDomainCertificateProgress?> GetPublicProgressAsync(
        string domain,
        CancellationToken cancellationToken)
    {
        var normalized = HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(domain);
        var currentCertificates = dbContext.DomainCertificates.AsNoTracking()
            .Where(item => item.IsCurrent);
        return await (
                from enrollment in dbContext.DomainEnrollments.AsNoTracking()
                    .Where(item => item.Domain == normalized && item.IsCurrent)
                join certificate in currentCertificates
                    on enrollment.EnrollmentId equals certificate.EnrollmentId into certificates
                from certificate in certificates.DefaultIfEmpty()
                select new PublicDomainCertificateProgress(
                    enrollment.Domain,
                    enrollment.Status,
                    enrollment.ApplicationStatus,
                    enrollment.SecurityReviewCompletedAtUtc,
                    enrollment.UnresolvedCriticalFindings,
                    certificate == null ? null : certificate.Status,
                    certificate == null ? null : certificate.Level))
            .SingleOrDefaultAsync(cancellationToken);
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
    public async Task<DomainEnrollmentTransitionWriteResult> TryApplyWebsiteVerificationAsync(
        DomainWebsiteVerificationRecord verification,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verification);
        ValidateIdentifier(verification.EnrollmentId, 128);
        ValidateIdentifier(verification.OwnerId, 256);
        ValidateIdentifier(verification.AuditEventId, 128);
        var domain = HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(verification.Domain);
        if (domain != verification.Domain ||
            verification.Method != HIP.Domain.Identity.VerificationMethod.WellKnownHipJson ||
            verification.VerifiedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Website verification state is invalid.", nameof(verification));
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
        if (enrollment.Status != DomainEnrollmentStatus.OwnershipVerified)
        {
            return new DomainEnrollmentTransitionWriteResult(
                enrollment.WebsiteVerifiedAtUtc is not null &&
                enrollment.Status is DomainEnrollmentStatus.PendingSecurityReview or DomainEnrollmentStatus.Verified or DomainEnrollmentStatus.Monitored
                    ? DomainEnrollmentTransitionWriteStatus.AlreadyApplied
                    : DomainEnrollmentTransitionWriteStatus.Conflict);
        }
        if (enrollment.DnsVerifiedAtUtc is null || await dbContext.DomainCertificateEvents.AnyAsync(
                item => item.EventId == verification.AuditEventId,
                cancellationToken))
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.Conflict);
        }

        DomainEnrollmentLifecycle.RequireTransition(
            enrollment.Status,
            DomainEnrollmentStatus.PendingSecurityReview);
        var previous = enrollment.Status;
        enrollment.Status = DomainEnrollmentStatus.PendingSecurityReview;
        enrollment.WebsiteVerifiedAtUtc = verification.VerifiedAtUtc;
        enrollment.UpdatedAtUtc = verification.VerifiedAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = verification.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = null,
            EventType = "WebsiteControlVerified",
            PreviousStatus = previous.ToString(),
            CurrentStatus = enrollment.Status.ToString(),
            ActorId = verification.OwnerId,
            PublicSummary = "HIP verified website control through the fixed HTTPS well-known path.",
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
    public async Task<DomainEnrollmentTransitionWriteResult> TryCompleteIdentityProfileAsync(
        DomainCertificateIdentityProfileRecord profile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ValidateIdentifier(profile.EnrollmentId, 128);
        ValidateIdentifier(profile.OwnerId, 256);
        ValidateIdentifier(profile.AuditEventId, 128);
        ValidateProfileText(profile.PublicDisplayName, 200, required: true);
        ValidateProfileText(profile.PublicOrganizationName, 200);
        ValidateProfileText(profile.PublicWebsiteContact, 320);
        ValidateProfileText(profile.PublicCountryOrRegion, 100);
        if (profile.SecurityContactHash.Length != 71 ||
            !profile.SecurityContactHash.StartsWith("sha256:", StringComparison.Ordinal) ||
            !profile.SecurityContactHash[7..].All(Uri.IsHexDigit) ||
            profile.CompletedAtUtc.Offset != TimeSpan.Zero ||
            HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(profile.Domain) != profile.Domain)
        {
            throw new ArgumentException("Certificate identity profile is invalid.", nameof(profile));
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == profile.EnrollmentId && item.OwnerId == profile.OwnerId &&
                    item.Domain == profile.Domain && item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.NotFound);
        }
        if (enrollment.Status != DomainEnrollmentStatus.PendingSecurityReview ||
            enrollment.DnsVerifiedAtUtc is null || enrollment.WebsiteVerifiedAtUtc is null)
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.Conflict);
        }
        if (enrollment.IdentityCompletedAtUtc is not null)
        {
            var exact = enrollment.PublicDisplayName == profile.PublicDisplayName &&
                enrollment.PublicOrganizationName == profile.PublicOrganizationName &&
                enrollment.PublicWebsiteContact == profile.PublicWebsiteContact &&
                enrollment.PublicCountryOrRegion == profile.PublicCountryOrRegion &&
                enrollment.SecurityContactHash == profile.SecurityContactHash;
            return new DomainEnrollmentTransitionWriteResult(exact
                ? DomainEnrollmentTransitionWriteStatus.AlreadyApplied
                : DomainEnrollmentTransitionWriteStatus.Conflict);
        }
        if (await dbContext.DomainCertificateEvents.AnyAsync(item => item.EventId == profile.AuditEventId, cancellationToken))
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.Conflict);
        }

        enrollment.PublicDisplayName = profile.PublicDisplayName;
        enrollment.PublicOrganizationName = profile.PublicOrganizationName;
        enrollment.PublicWebsiteContact = profile.PublicWebsiteContact;
        enrollment.PublicCountryOrRegion = profile.PublicCountryOrRegion;
        enrollment.SecurityContactHash = profile.SecurityContactHash;
        enrollment.IdentityCompletedAtUtc = profile.CompletedAtUtc;
        enrollment.UpdatedAtUtc = profile.CompletedAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = profile.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = null,
            EventType = "IdentityProfileCompleted",
            PreviousStatus = enrollment.Status.ToString(),
            CurrentStatus = enrollment.Status.ToString(),
            ActorId = profile.OwnerId,
            PublicSummary = "The certificate identity profile was completed with owner-selected public fields.",
            PolicyVersion = enrollment.PolicyVersion,
            OccurredAtUtc = profile.CompletedAtUtc
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
    public async Task<DomainEnrollmentTransitionWriteResult> TrySubmitApplicationAsync(
        DomainCertificateApplicationSubmissionRecord submission,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(submission);
        ValidateIdentifier(submission.EnrollmentId, 128);
        ValidateIdentifier(submission.OwnerId, 256);
        ValidateIdentifier(submission.AttestationVersion, 128);
        ValidateIdentifier(submission.AuditEventId, 128);
        if (!IsDigest(submission.AttestationDigest) ||
            submission.SubmittedAtUtc.Offset != TimeSpan.Zero ||
            HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(submission.Domain) != submission.Domain)
        {
            throw new ArgumentException("Certificate application submission is invalid.", nameof(submission));
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == submission.EnrollmentId &&
                    item.OwnerId == submission.OwnerId &&
                    item.Domain == submission.Domain &&
                    item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return new(DomainEnrollmentTransitionWriteStatus.NotFound);
        }
        if (enrollment.ApplicationStatus == DomainCertificateApplicationStatus.Submitted &&
            enrollment.ApplicantAttestationDigest == submission.AttestationDigest)
        {
            return new(DomainEnrollmentTransitionWriteStatus.AlreadyApplied);
        }
        if (enrollment.Status != DomainEnrollmentStatus.PendingSecurityReview ||
            enrollment.IdentityCompletedAtUtc is null ||
            enrollment.DnsVerifiedAtUtc is null ||
            enrollment.WebsiteVerifiedAtUtc is null ||
            enrollment.ApplicationStatus is not DomainCertificateApplicationStatus.Draft
                and not DomainCertificateApplicationStatus.ChangesRequested)
        {
            return new(DomainEnrollmentTransitionWriteStatus.Conflict);
        }
        if (await dbContext.DomainCertificateEvents.AnyAsync(
                item => item.EventId == submission.AuditEventId,
                cancellationToken))
        {
            return new(DomainEnrollmentTransitionWriteStatus.Conflict);
        }

        enrollment.ApplicationStatus = DomainCertificateApplicationStatus.Submitted;
        enrollment.ApplicationSubmittedAtUtc = submission.SubmittedAtUtc;
        enrollment.ApplicationReviewedAtUtc = null;
        enrollment.ApplicantAttestationDigest = submission.AttestationDigest;
        enrollment.ApplicationDecisionReason = null;
        enrollment.UpdatedAtUtc = submission.SubmittedAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = submission.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            EventType = "CertificateApplicationSubmitted",
            PreviousStatus = DomainCertificateApplicationStatus.Draft.ToString(),
            CurrentStatus = DomainCertificateApplicationStatus.Submitted.ToString(),
            ActorId = submission.OwnerId,
            ReasonCode = submission.AttestationVersion,
            PublicSummary = "The authenticated domain representative submitted a certificate application.",
            PolicyVersion = enrollment.PolicyVersion,
            EvidenceDigest = submission.AttestationDigest,
            OccurredAtUtc = submission.SubmittedAtUtc
        });
        return await SaveApplicationTransitionAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<DomainEnrollmentTransitionWriteResult> TryDecideApplicationAsync(
        DomainCertificateApplicationDecisionRecord decision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ValidateIdentifier(decision.EnrollmentId, 128);
        ValidateIdentifier(decision.ActorId, 256);
        ValidateIdentifier(decision.AuditEventId, 128);
        ValidateProfileText(decision.Reason, 500, required: true);
        if (decision.Decision is not DomainCertificateApplicationStatus.Approved
                and not DomainCertificateApplicationStatus.ChangesRequested
                and not DomainCertificateApplicationStatus.Denied ||
            decision.DecidedAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Certificate application decision is invalid.", nameof(decision));
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == decision.EnrollmentId && item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return new(DomainEnrollmentTransitionWriteStatus.NotFound);
        }
        if (enrollment.ApplicationStatus == decision.Decision)
        {
            return new(DomainEnrollmentTransitionWriteStatus.AlreadyApplied);
        }
        if (enrollment.ApplicationStatus != DomainCertificateApplicationStatus.Submitted ||
            enrollment.ApplicantAttestationDigest is null ||
            await dbContext.DomainCertificateEvents.AnyAsync(
                item => item.EventId == decision.AuditEventId,
                cancellationToken))
        {
            return new(DomainEnrollmentTransitionWriteStatus.Conflict);
        }

        var previous = enrollment.ApplicationStatus;
        enrollment.ApplicationStatus = decision.Decision;
        enrollment.ApplicationReviewedAtUtc = decision.DecidedAtUtc;
        enrollment.ApplicationDecisionReason = decision.Reason;
        enrollment.UpdatedAtUtc = decision.DecidedAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = decision.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            EventType = decision.Decision switch
            {
                DomainCertificateApplicationStatus.Approved => "CertificateApplicationApproved",
                DomainCertificateApplicationStatus.ChangesRequested => "CertificateApplicationChangesRequested",
                _ => "CertificateApplicationDenied"
            },
            PreviousStatus = previous.ToString(),
            CurrentStatus = decision.Decision.ToString(),
            ActorId = decision.ActorId,
            ReasonCode = decision.Decision.ToString(),
            PublicSummary = decision.Decision switch
            {
                DomainCertificateApplicationStatus.Approved => "HIP approved the authenticated certificate application.",
                DomainCertificateApplicationStatus.ChangesRequested => "HIP requested changes to the certificate application.",
                _ => "HIP denied the certificate application."
            },
            PolicyVersion = enrollment.PolicyVersion,
            EvidenceDigest = enrollment.ApplicantAttestationDigest,
            OccurredAtUtc = decision.DecidedAtUtc
        });
        return await SaveApplicationTransitionAsync(cancellationToken);
    }

    private async Task<DomainEnrollmentTransitionWriteResult> SaveApplicationTransitionAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return new(DomainEnrollmentTransitionWriteStatus.Updated);
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            return new(DomainEnrollmentTransitionWriteStatus.Conflict);
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<DomainMonitoringEnrollmentState>> ListDueAsync(
        DateTimeOffset dueAtUtc,
        int maximum,
        CancellationToken cancellationToken)
    {
        if (dueAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("The monitoring due time must be UTC.", nameof(dueAtUtc));
        }
        if (maximum is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(maximum));
        }

        return await (
                from enrollment in dbContext.DomainEnrollments.AsNoTracking()
                    .Where(item => item.IsCurrent &&
                                   item.MonitoringEnabledAtUtc != null &&
                                   item.MonitoringNextCheckAtUtc != null &&
                                   item.MonitoringNextCheckAtUtc <= dueAtUtc &&
                                   (item.Status == DomainEnrollmentStatus.Verified ||
                                    item.Status == DomainEnrollmentStatus.Monitored))
                join certificate in dbContext.DomainCertificates.AsNoTracking()
                        .Where(item => item.IsCurrent &&
                                       item.Status == DomainCertificateStatus.Active &&
                                       item.ExpiresAtUtc > dueAtUtc)
                    on enrollment.EnrollmentId equals certificate.EnrollmentId
                orderby enrollment.MonitoringNextCheckAtUtc, enrollment.EnrollmentId
                select new DomainMonitoringEnrollmentState(
                    enrollment.EnrollmentId,
                    enrollment.OwnerId,
                    enrollment.Domain,
                    enrollment.Status,
                    certificate.Status,
                    certificate.Level,
                    enrollment.DnsVerifiedAtUtc,
                    enrollment.WebsiteVerifiedAtUtc,
                    enrollment.IdentityCompletedAtUtc,
                    enrollment.MonitoringEnabledAtUtc,
                    enrollment.LastMonitoringAtUtc,
                    enrollment.CurrentScore,
                    enrollment.MonitoringNextCheckAtUtc,
                    enrollment.MonitoringFailureCount))
            .Take(maximum)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<DomainMonitoringWriteStatus> TryRecordFailureAsync(
        DomainMonitoringFailureRecord record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        ValidateIdentifier(record.EnrollmentId, 128);
        ValidateIdentifier(record.OwnerId, 256);
        ValidateIdentifier(record.AuditEventId, 128);
        if (record.ExpectedFailureCount < 0 ||
            record.FailedAtUtc.Offset != TimeSpan.Zero ||
            record.NextCheckAtUtc <= record.FailedAtUtc ||
            HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(record.Domain) != record.Domain)
        {
            throw new ArgumentException("Domain monitoring failure state is invalid.", nameof(record));
        }

        var existingEvent = await dbContext.DomainCertificateEvents.AsNoTracking()
            .SingleOrDefaultAsync(item => item.EventId == record.AuditEventId, cancellationToken);
        if (existingEvent is not null)
        {
            return existingEvent.EnrollmentId == record.EnrollmentId &&
                   existingEvent.EventType == "MonitoringCheckDeferred"
                ? DomainMonitoringWriteStatus.Existing
                : DomainMonitoringWriteStatus.Conflict;
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == record.EnrollmentId &&
                    item.OwnerId == record.OwnerId &&
                    item.Domain == record.Domain &&
                    item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return DomainMonitoringWriteStatus.NotFound;
        }
        var certificate = await dbContext.DomainCertificates.AsNoTracking().SingleOrDefaultAsync(
            item => item.EnrollmentId == enrollment.EnrollmentId && item.IsCurrent,
            cancellationToken);
        if (certificate is null || certificate.Status != DomainCertificateStatus.Active ||
            enrollment.MonitoringEnabledAtUtc is null ||
            enrollment.MonitoringFailureCount != record.ExpectedFailureCount)
        {
            return DomainMonitoringWriteStatus.Conflict;
        }

        enrollment.MonitoringFailureCount = checked(record.ExpectedFailureCount + 1);
        enrollment.MonitoringNextCheckAtUtc = record.NextCheckAtUtc;
        enrollment.UpdatedAtUtc = record.FailedAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = record.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = certificate.CertificateId,
            EventType = "MonitoringCheckDeferred",
            PreviousStatus = enrollment.Status.ToString(),
            CurrentStatus = enrollment.Status.ToString(),
            ActorId = "hip-monitoring-service",
            ReasonCode = "EvidenceUnavailable",
            PublicSummary = "HIP deferred the monitoring check and scheduled a privacy-safe retry.",
            PolicyVersion = enrollment.PolicyVersion,
            OccurredAtUtc = record.FailedAtUtc
        });
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return DomainMonitoringWriteStatus.Updated;
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            return DomainMonitoringWriteStatus.Conflict;
        }
    }
    /// <inheritdoc />
    public async Task<DomainMonitoringWriteStatus> TryEnableAsync(
        DomainMonitoringEnableRecord record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        ValidateIdentifier(record.EnrollmentId, 128);
        ValidateIdentifier(record.OwnerId, 256);
        ValidateIdentifier(record.AuditEventId, 128);
        if (record.EnabledAtUtc.Offset != TimeSpan.Zero || record.NextCheckAtUtc < record.EnabledAtUtc ||
            HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(record.Domain) != record.Domain)
        {
            throw new ArgumentException("Domain monitoring opt-in is invalid.", nameof(record));
        }

        var existingEvent = await dbContext.DomainCertificateEvents.AsNoTracking()
            .SingleOrDefaultAsync(item => item.EventId == record.AuditEventId, cancellationToken);
        if (existingEvent is not null)
        {
            return existingEvent.EnrollmentId == record.EnrollmentId && existingEvent.EventType == "MonitoringEnabled"
                ? DomainMonitoringWriteStatus.Existing
                : DomainMonitoringWriteStatus.Conflict;
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == record.EnrollmentId && item.OwnerId == record.OwnerId &&
                    item.Domain == record.Domain && item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return DomainMonitoringWriteStatus.NotFound;
        }
        var certificate = await dbContext.DomainCertificates.AsNoTracking().SingleOrDefaultAsync(
            item => item.EnrollmentId == enrollment.EnrollmentId && item.IsCurrent,
            cancellationToken);
        if (certificate is null || certificate.Status != DomainCertificateStatus.Active ||
            enrollment.Status is not DomainEnrollmentStatus.Verified and not DomainEnrollmentStatus.Monitored)
        {
            return DomainMonitoringWriteStatus.Conflict;
        }

        enrollment.MonitoringEnabledAtUtc ??= record.EnabledAtUtc;
        enrollment.MonitoringNextCheckAtUtc = record.NextCheckAtUtc;
        enrollment.MonitoringFailureCount = 0;
        enrollment.UpdatedAtUtc = record.EnabledAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = record.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = certificate.CertificateId,
            EventType = "MonitoringEnabled",
            PreviousStatus = enrollment.Status.ToString(),
            CurrentStatus = enrollment.Status.ToString(),
            ActorId = record.OwnerId,
            ReasonCode = "OwnerOptIn",
            PublicSummary = "The authenticated domain owner enabled privacy-safe HIP monitoring.",
            PolicyVersion = enrollment.PolicyVersion,
            OccurredAtUtc = record.EnabledAtUtc
        });
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return DomainMonitoringWriteStatus.Updated;
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            return DomainMonitoringWriteStatus.Conflict;
        }
    }

    /// <inheritdoc />
    public async Task<DomainMonitoringWriteStatus> TryApplyCheckAsync(
        DomainMonitoringCheckRecord record,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        ValidateIdentifier(record.EnrollmentId, 128);
        ValidateIdentifier(record.OwnerId, 256);
        ValidateIdentifier(record.AuditEventId, 128);
        if (record.CurrentScore is < 0 or > 100 || record.UnresolvedCriticalFindings < 0 ||
            record.CheckedAtUtc.Offset != TimeSpan.Zero || record.NextCheckAtUtc <= record.CheckedAtUtc ||
            !IsDigest(record.EvidenceDigest) ||
            HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(record.Domain) != record.Domain)
        {
            throw new ArgumentException("Domain monitoring check is invalid.", nameof(record));
        }
        if (record.ExpectedStatus != record.TargetStatus)
        {
            DomainEnrollmentLifecycle.RequireTransition(record.ExpectedStatus, record.TargetStatus);
        }

        var existingEvent = await dbContext.DomainCertificateEvents.AsNoTracking()
            .SingleOrDefaultAsync(item => item.EventId == record.AuditEventId, cancellationToken);
        if (existingEvent is not null)
        {
            return existingEvent.EnrollmentId == record.EnrollmentId && existingEvent.EvidenceDigest == record.EvidenceDigest
                ? DomainMonitoringWriteStatus.Existing
                : DomainMonitoringWriteStatus.Conflict;
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == record.EnrollmentId && item.OwnerId == record.OwnerId &&
                    item.Domain == record.Domain && item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return DomainMonitoringWriteStatus.NotFound;
        }
        var certificate = await dbContext.DomainCertificates.AsNoTracking().SingleOrDefaultAsync(
            item => item.EnrollmentId == enrollment.EnrollmentId && item.IsCurrent,
            cancellationToken);
        if (certificate is null || certificate.Status != DomainCertificateStatus.Active ||
            enrollment.MonitoringEnabledAtUtc is null || enrollment.Status != record.ExpectedStatus)
        {
            return DomainMonitoringWriteStatus.Conflict;
        }

        var previous = enrollment.Status;
        enrollment.Status = record.TargetStatus;
        enrollment.LastMonitoringAtUtc = record.CheckedAtUtc;
        enrollment.MonitoringNextCheckAtUtc = record.NextCheckAtUtc;
        enrollment.MonitoringFailureCount = 0;
        enrollment.CurrentScore = record.CurrentScore;
        enrollment.UnresolvedCriticalFindings = record.UnresolvedCriticalFindings;
        enrollment.UpdatedAtUtc = record.CheckedAtUtc;
        enrollment.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = record.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = certificate.CertificateId,
            EventType = record.TargetStatus == DomainEnrollmentStatus.Monitored
                ? "MonitoringPolicySatisfied"
                : "MonitoringEvidenceUpdated",
            PreviousStatus = previous.ToString(),
            CurrentStatus = record.TargetStatus.ToString(),
            ActorId = "hip-monitoring-service",
            ReasonCode = record.TargetStatus == DomainEnrollmentStatus.Monitored ? "Eligible" : "GatheringEvidence",
            PublicSummary = record.TargetStatus == DomainEnrollmentStatus.Monitored
                ? "Fresh authoritative evidence satisfied the HIP monitored-domain policy."
                : "HIP stored a fresh privacy-safe monitoring result; monitored-domain requirements are not yet satisfied.",
            PolicyVersion = enrollment.PolicyVersion,
            EvidenceDigest = record.EvidenceDigest,
            OccurredAtUtc = record.CheckedAtUtc
        });
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return DomainMonitoringWriteStatus.Updated;
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            return DomainMonitoringWriteStatus.Conflict;
        }
    }
    /// <inheritdoc />
    public async Task<DomainEnrollmentTransitionWriteResult> TryApplySecurityReviewAsync(
        DomainCertificateSecurityReviewRecord review,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(review);
        ValidateIdentifier(review.EnrollmentId, 128);
        ValidateIdentifier(review.OwnerId, 256);
        ValidateIdentifier(review.AuditEventId, 128);
        if (review.CurrentScore is < 0 or > 100 || review.UnresolvedCriticalFindings < 0 ||
            review.ReviewedAtUtc.Offset != TimeSpan.Zero || !IsDigest(review.EvidenceDigest) ||
            HIP.Application.PublicLookup.DomainInputValidator.ValidateAndNormalize(review.Domain) != review.Domain)
        {
            throw new ArgumentException("Certificate security review is invalid.", nameof(review));
        }

        var existingEvent = await dbContext.DomainCertificateEvents.AsNoTracking()
            .SingleOrDefaultAsync(item => item.EventId == review.AuditEventId, cancellationToken);
        if (existingEvent is not null)
        {
            return new DomainEnrollmentTransitionWriteResult(
                existingEvent.EnrollmentId == review.EnrollmentId && existingEvent.EvidenceDigest == review.EvidenceDigest
                    ? DomainEnrollmentTransitionWriteStatus.AlreadyApplied
                    : DomainEnrollmentTransitionWriteStatus.Conflict);
        }

        var enrollment = await dbContext.DomainEnrollments.SingleOrDefaultAsync(
            item => item.EnrollmentId == review.EnrollmentId && item.OwnerId == review.OwnerId &&
                    item.Domain == review.Domain && item.IsCurrent,
            cancellationToken);
        if (enrollment is null)
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.NotFound);
        }
        if (enrollment.Status != DomainEnrollmentStatus.PendingSecurityReview ||
            enrollment.IdentityCompletedAtUtc is null || enrollment.DnsVerifiedAtUtc is null ||
            enrollment.WebsiteVerifiedAtUtc is null ||
            enrollment.ApplicationStatus != DomainCertificateApplicationStatus.Approved)
        {
            return new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.Conflict);
        }

        var previous = enrollment.Status;
        if (review.Decision == DomainCertificatePolicyDecision.Eligible)
        {
            DomainEnrollmentLifecycle.RequireTransition(previous, DomainEnrollmentStatus.Verified);
            enrollment.Status = DomainEnrollmentStatus.Verified;
        }
        enrollment.SecurityReviewCompletedAtUtc = review.ReviewedAtUtc;
        enrollment.CurrentScore = review.CurrentScore;
        enrollment.UnresolvedCriticalFindings = review.UnresolvedCriticalFindings;
        enrollment.UpdatedAtUtc = review.ReviewedAtUtc;
        enrollment.AggregateVersion++;
        var eventType = review.Decision switch
        {
            DomainCertificatePolicyDecision.Eligible => "SecurityReviewPassed",
            DomainCertificatePolicyDecision.RequiresReview => "SecurityReviewQueued",
            _ => "SecurityReviewRequirementsMissing"
        };
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = review.AuditEventId,
            EnrollmentId = enrollment.EnrollmentId,
            CertificateId = null,
            EventType = eventType,
            PreviousStatus = previous.ToString(),
            CurrentStatus = enrollment.Status.ToString(),
            ActorId = review.OwnerId,
            ReasonCode = review.Decision.ToString(),
            PublicSummary = review.Decision switch
            {
                DomainCertificatePolicyDecision.Eligible =>
                    "HIP's server-owned security review satisfied the requested certificate policy.",
                DomainCertificatePolicyDecision.RequiresReview =>
                    "HIP's server-owned security review requires an authorized decision.",
                _ => "HIP's server-owned security review found missing certificate requirements."
            },
            PolicyVersion = enrollment.PolicyVersion,
            EvidenceDigest = review.EvidenceDigest,
            OccurredAtUtc = review.ReviewedAtUtc
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
    private static void ValidateProfileText(string? value, int maximumLength, bool required = false)
    {
        if ((required && string.IsNullOrWhiteSpace(value)) || value?.Length > maximumLength ||
            value?.Any(character => char.IsControl(character) || char.IsSurrogate(character)) == true)
        {
            throw new ArgumentException("Certificate identity profile text is invalid.");
        }
    }

    /// <inheritdoc />
    public async Task<DomainCertificateTransitionWriteResult> TryTransitionStatusAsync(
        DomainCertificateStatusTransition transition,
        CancellationToken cancellationToken)
    {
        ValidateTransition(transition);
        var existingEvent = await FindTransitionEventAsync(transition, cancellationToken);
        if (existingEvent is not null)
        {
            return existingEvent;
        }

        var certificate = await dbContext.DomainCertificates.SingleOrDefaultAsync(
            item => item.CertificateId == transition.CertificateId &&
                    item.IsCurrent &&
                    item.SignedCertificateJson != null,
            cancellationToken);
        if (certificate is null)
        {
            return new DomainCertificateTransitionWriteResult(DomainCertificateTransitionWriteStatus.NotFound);
        }
        if (certificate.Status != transition.ExpectedStatus)
        {
            return new DomainCertificateTransitionWriteResult(DomainCertificateTransitionWriteStatus.Conflict);
        }

        certificate.Status = transition.TargetStatus;
        certificate.AggregateVersion++;
        dbContext.DomainCertificateEvents.Add(new HipDomainCertificateEventEntity
        {
            EventId = transition.EventId,
            EnrollmentId = certificate.EnrollmentId,
            CertificateId = certificate.CertificateId,
            EventType = TransitionEventType(transition.TargetStatus),
            PreviousStatus = transition.ExpectedStatus.ToString(),
            CurrentStatus = transition.TargetStatus.ToString(),
            ActorId = transition.ActorId,
            ReasonCode = transition.ReasonCode,
            PublicSummary = transition.PublicSummary,
            PolicyVersion = certificate.PolicyVersion,
            EvidenceDigest = certificate.SourceDecisionDigest,
            OccurredAtUtc = transition.OccurredAtUtc
        });
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
            return new DomainCertificateTransitionWriteResult(DomainCertificateTransitionWriteStatus.Updated);
        }
        catch (DbUpdateException)
        {
            dbContext.ChangeTracker.Clear();
            return await FindTransitionEventAsync(transition, cancellationToken)
                ?? new DomainCertificateTransitionWriteResult(DomainCertificateTransitionWriteStatus.Conflict);
        }
    }

    private async Task<DomainCertificateTransitionWriteResult?> FindTransitionEventAsync(
        DomainCertificateStatusTransition transition,
        CancellationToken cancellationToken)
    {
        var item = await dbContext.DomainCertificateEvents.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.EventId == transition.EventId, cancellationToken);
        if (item is null)
        {
            return null;
        }
        var exact = item.CertificateId == transition.CertificateId &&
                    item.PreviousStatus == transition.ExpectedStatus.ToString() &&
                    item.CurrentStatus == transition.TargetStatus.ToString() &&
                    item.ActorId == transition.ActorId &&
                    item.ReasonCode == transition.ReasonCode &&
                    item.PublicSummary == transition.PublicSummary &&
                    item.OccurredAtUtc == transition.OccurredAtUtc;
        return new DomainCertificateTransitionWriteResult(
            exact ? DomainCertificateTransitionWriteStatus.ExistingSame : DomainCertificateTransitionWriteStatus.Conflict);
    }

    private static void ValidateTransition(DomainCertificateStatusTransition transition)
    {
        ArgumentNullException.ThrowIfNull(transition);
        ValidateIdentifier(transition.CertificateId, 128);
        ValidateIdentifier(transition.ActorId, 256);
        ValidateIdentifier(transition.EventId, 128);
        ValidateIdentifier(transition.ReasonCode, 120);
        DomainCertificateLifecycle.RequireTransition(transition.ExpectedStatus, transition.TargetStatus);
        DomainCertificateLifecycle.RequireReason(transition.TargetStatus, transition.PublicSummary);
        if (transition.PublicSummary.Length > 500 || transition.PublicSummary.Any(char.IsControl) ||
            transition.OccurredAtUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Certificate status transition metadata is invalid.", nameof(transition));
        }
    }

    private static string TransitionEventType(DomainCertificateStatus targetStatus) => targetStatus switch
    {
        DomainCertificateStatus.Suspended => "CertificateSuspended",
        DomainCertificateStatus.Active => "CertificateReinstated",
        DomainCertificateStatus.Revoked => "CertificateRevoked",
        _ => throw new ArgumentOutOfRangeException(nameof(targetStatus))
    };


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
