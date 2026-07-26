using System.Security.Cryptography;
using System.Text;
using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

public enum DomainCertificateApplicationSubmissionStatus
{
    Submitted,
    Existing,
    NotReady,
    InvalidRequest,
    Conflict
}

public sealed record DomainCertificateApplicationSubmissionResult(
    DomainCertificateApplicationSubmissionStatus Status,
    string? AttestationDigest = null);

public enum DomainCertificateApplicationDecisionStatus
{
    Approved,
    ChangesRequested,
    Denied,
    Existing,
    InvalidRequest,
    NotFound,
    Conflict
}

public sealed record DomainCertificateApplicationDecisionResult(
    DomainCertificateApplicationDecisionStatus Status);

public interface IDomainCertificateApplicationService
{
    Task<DomainCertificateApplicationSubmissionResult> SubmitAsync(
        string ownerId,
        string domain,
        bool authorityConfirmed,
        bool accuracyConfirmed,
        CancellationToken cancellationToken);

    Task<DomainCertificateApplicationDecisionResult> DecideAsync(
        string enrollmentId,
        DomainCertificateApplicationStatus decision,
        string reason,
        string actorId,
        CancellationToken cancellationToken);
}

/// <summary>Creates authenticated application attestations and authorized, permanently audited decisions.</summary>
public sealed class DomainCertificateApplicationService(
    IDomainEnrollmentRepository repository,
    TimeProvider timeProvider) : IDomainCertificateApplicationService
{
    public async Task<DomainCertificateApplicationSubmissionResult> SubmitAsync(
        string ownerId,
        string domain,
        bool authorityConfirmed,
        bool accuracyConfirmed,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ownerId) || !authorityConfirmed || !accuracyConfirmed)
        {
            return new(DomainCertificateApplicationSubmissionStatus.InvalidRequest);
        }

        var normalized = PublicLookup.DomainInputValidator.ValidateAndNormalize(domain);
        var enrollment = await repository.GetCurrentAsync(ownerId, normalized, cancellationToken)
            .ConfigureAwait(false);
        if (enrollment is null ||
            enrollment.DnsVerifiedAtUtc is null ||
            enrollment.WebsiteVerifiedAtUtc is null ||
            enrollment.IdentityCompletedAtUtc is null)
        {
            return new(DomainCertificateApplicationSubmissionStatus.NotReady);
        }

        var digest = AttestationDigest(enrollment, normalized);
        var submittedAtUtc = timeProvider.GetUtcNow();
        var write = await repository.TrySubmitApplicationAsync(
                new DomainCertificateApplicationSubmissionRecord(
                    enrollment.EnrollmentId,
                    ownerId,
                    normalized,
                    DomainCertificateApplicantAttestation.Version,
                    digest,
                    submittedAtUtc,
                    $"certificate-event:application:{digest[7..55]}"),
                cancellationToken)
            .ConfigureAwait(false);
        return write.Status switch
        {
            DomainEnrollmentTransitionWriteStatus.Updated =>
                new(DomainCertificateApplicationSubmissionStatus.Submitted, digest),
            DomainEnrollmentTransitionWriteStatus.AlreadyApplied =>
                new(DomainCertificateApplicationSubmissionStatus.Existing, digest),
            _ => new(DomainCertificateApplicationSubmissionStatus.Conflict)
        };
    }

    public async Task<DomainCertificateApplicationDecisionResult> DecideAsync(
        string enrollmentId,
        DomainCertificateApplicationStatus decision,
        string reason,
        string actorId,
        CancellationToken cancellationToken)
    {
        var trimmedReason = reason?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(enrollmentId) ||
            string.IsNullOrWhiteSpace(actorId) ||
            decision is not DomainCertificateApplicationStatus.Approved
                and not DomainCertificateApplicationStatus.ChangesRequested
                and not DomainCertificateApplicationStatus.Denied ||
            trimmedReason.Length is < 5 or > 500 ||
            trimmedReason.Any(char.IsControl))
        {
            return new(DomainCertificateApplicationDecisionStatus.InvalidRequest);
        }

        var decidedAtUtc = timeProvider.GetUtcNow();
        var eventId = $"certificate-event:decision:{Guid.NewGuid():N}";
        var write = await repository.TryDecideApplicationAsync(
                new DomainCertificateApplicationDecisionRecord(
                    enrollmentId,
                    decision,
                    trimmedReason,
                    actorId,
                    decidedAtUtc,
                    eventId),
                cancellationToken)
            .ConfigureAwait(false);
        return write.Status switch
        {
            DomainEnrollmentTransitionWriteStatus.Updated => new(decision switch
            {
                DomainCertificateApplicationStatus.Approved => DomainCertificateApplicationDecisionStatus.Approved,
                DomainCertificateApplicationStatus.ChangesRequested => DomainCertificateApplicationDecisionStatus.ChangesRequested,
                _ => DomainCertificateApplicationDecisionStatus.Denied
            }),
            DomainEnrollmentTransitionWriteStatus.AlreadyApplied =>
                new(DomainCertificateApplicationDecisionStatus.Existing),
            DomainEnrollmentTransitionWriteStatus.NotFound =>
                new(DomainCertificateApplicationDecisionStatus.NotFound),
            _ => new(DomainCertificateApplicationDecisionStatus.Conflict)
        };
    }

    private static string AttestationDigest(DomainEnrollmentStateRecord enrollment, string domain)
    {
        var value = string.Join(
            '\n',
            DomainCertificateApplicantAttestation.Version,
            enrollment.EnrollmentId,
            domain,
            enrollment.PublicDisplayName,
            enrollment.PublicOrganizationName,
            DomainCertificateApplicantAttestation.AuthorityStatement,
            DomainCertificateApplicantAttestation.AccuracyStatement);
        return $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()}";
    }
}
