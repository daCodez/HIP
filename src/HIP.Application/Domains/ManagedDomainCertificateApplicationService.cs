using System.Collections.Concurrent;
using HIP.Application.Certificates;
using HIP.Domain.Certificates;

namespace HIP.Application.Domains;

/// <summary>Server-owned evidence and review signals used for one managed-domain eligibility evaluation.</summary>
public sealed record ManagedDomainCertificationEvidence(
    DomainCertificateEvidenceSnapshot Evidence,
    DomainCertificateReviewSignals ReviewSignals);

/// <summary>Resolves authoritative certification evidence without trusting application request bodies.</summary>
public interface IManagedDomainCertificationEvidenceSource
{
    /// <summary>Returns current server-owned evidence for the stable domain.</summary>
    Task<ManagedDomainCertificationEvidence> GetAsync(
        string domainId,
        string domainName,
        CancellationToken cancellationToken);
}

/// <summary>Persisted certificate application tied to a stable managed-domain identity.</summary>
public sealed record ManagedDomainCertificateApplication(
    string ApplicationId,
    string DomainId,
    string DomainName,
    DomainCertificateLevel RequestedLevel,
    string ApplicantId,
    string? OrganizationId,
    DomainCertificateApplicationStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? SubmittedAtUtc,
    DomainCertificatePolicyEvaluationResult? Eligibility,
    IReadOnlyCollection<string> SecurityFindings,
    IReadOnlyCollection<string> RequiredRemediation,
    string? ReviewerId,
    string? ReviewerNotes,
    string? Decision,
    DateTimeOffset? DecisionAtUtc,
    long Version);

/// <summary>Persistence boundary that retains every managed-domain application as an independent record.</summary>
public interface IManagedDomainCertificateApplicationRepository
{
    Task<ManagedDomainCertificateApplication?> GetAsync(string applicationId, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<ManagedDomainCertificateApplication>> ListByDomainAsync(string domainId, CancellationToken cancellationToken);
    Task AddAsync(ManagedDomainCertificateApplication application, CancellationToken cancellationToken);
    Task UpdateAsync(ManagedDomainCertificateApplication application, long expectedVersion, CancellationToken cancellationToken);
}

/// <summary>Creates and evaluates authorization-safe certificate applications without overwriting earlier outcomes.</summary>
public sealed class ManagedDomainCertificateApplicationService(
    IDomainManagementService domainManagement,
    IManagedDomainCertificateApplicationRepository repository,
    IManagedDomainCertificationEvidenceSource evidenceSource,
    IDomainCertificatePolicyEvaluator eligibilityEvaluator,
    TimeProvider timeProvider)
{
    /// <summary>Gets one application only when its domain is visible to the actor.</summary>
    public Task<ManagedDomainCertificateApplication> GetAsync(
        string actorId,
        string applicationId,
        CancellationToken cancellationToken) =>
        RequireApplicationAsync(actorId, applicationId, cancellationToken);

    /// <summary>Lists retained applications only after checking access to the domain.</summary>
    public async Task<IReadOnlyCollection<ManagedDomainCertificateApplication>> ListAsync(
        string actorId,
        string domainId,
        CancellationToken cancellationToken)
    {
        _ = await RequireDomainAsync(actorId, domainId, cancellationToken).ConfigureAwait(false);
        return await repository.ListByDomainAsync(domainId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a new draft only after domain control has been verified.</summary>
    public async Task<ManagedDomainCertificateApplication> CreateDraftAsync(
        string actorId,
        string domainId,
        DomainCertificateLevel requestedLevel,
        CancellationToken cancellationToken)
    {
        if (requestedLevel is not (DomainCertificateLevel.Registered or DomainCertificateLevel.Verified or DomainCertificateLevel.Certified))
        {
            throw new ArgumentException("A supported certification level is required.", nameof(requestedLevel));
        }
        var domain = await RequireDomainAsync(actorId, domainId, cancellationToken).ConfigureAwait(false);
        if (domain.VerificationStatus != HIP.Domain.Domains.ManagedDomainVerificationStatus.Verified ||
            domain.OwnershipVerifiedAtUtc is null)
        {
            throw new InvalidOperationException("Domain ownership must be verified before creating a certificate application.");
        }
        var now = timeProvider.GetUtcNow();
        var application = new ManagedDomainCertificateApplication(
            $"domain-application_{Guid.NewGuid():N}", domain.DomainId, domain.DomainName, requestedLevel,
            actorId, domain.OrganizationId, DomainCertificateApplicationStatus.Draft, now, null, null,
            [], [], null, null, null, null, 1);
        await repository.AddAsync(application, cancellationToken).ConfigureAwait(false);
        return application;
    }

    /// <summary>Evaluates current server-owned evidence and routes the application deterministically.</summary>
    public async Task<ManagedDomainCertificateApplication> SubmitAsync(
        string actorId,
        string applicationId,
        CancellationToken cancellationToken)
    {
        var application = await RequireApplicationAsync(actorId, applicationId, cancellationToken).ConfigureAwait(false);
        if (application.Status is not (DomainCertificateApplicationStatus.Draft or DomainCertificateApplicationStatus.ActionRequired or DomainCertificateApplicationStatus.ChangesRequested))
        {
            throw new InvalidOperationException("This certificate application cannot be submitted from its current state.");
        }
        var evidence = await evidenceSource.GetAsync(application.DomainId, application.DomainName, cancellationToken).ConfigureAwait(false);
        var now = timeProvider.GetUtcNow();
        var evaluation = eligibilityEvaluator.Evaluate(new DomainCertificatePolicyEvaluationRequest(
            application.DomainName, application.RequestedLevel, evidence.Evidence, evidence.ReviewSignals, now));
        var status = evaluation.Decision switch
        {
            DomainCertificatePolicyDecision.Eligible => DomainCertificateApplicationStatus.Approved,
            DomainCertificatePolicyDecision.RequiresReview => DomainCertificateApplicationStatus.PendingReview,
            _ => DomainCertificateApplicationStatus.ActionRequired
        };
        var missing = evaluation.Requirements
            .Where(item => item.Status == DomainCertificateRequirementStatus.Missing)
            .Select(item => item.PublicSummary).ToArray();
        var findings = evaluation.Requirements
            .Where(item => item.Status != DomainCertificateRequirementStatus.Satisfied)
            .Select(item => item.Code).ToArray();
        var updated = application with
        {
            Status = status,
            SubmittedAtUtc = application.SubmittedAtUtc ?? now,
            Eligibility = evaluation,
            SecurityFindings = findings,
            RequiredRemediation = missing,
            Decision = status == DomainCertificateApplicationStatus.Approved ? "Automatically approved by versioned eligibility policy." : null,
            DecisionAtUtc = status == DomainCertificateApplicationStatus.Approved ? now : null,
            Version = application.Version + 1
        };
        await repository.UpdateAsync(updated, application.Version, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    /// <summary>Withdraws a non-terminal application while retaining it in domain history.</summary>
    public async Task<ManagedDomainCertificateApplication> WithdrawAsync(
        string actorId,
        string applicationId,
        CancellationToken cancellationToken)
    {
        var application = await RequireApplicationAsync(actorId, applicationId, cancellationToken).ConfigureAwait(false);
        if (application.Status is DomainCertificateApplicationStatus.Approved or DomainCertificateApplicationStatus.Rejected
            or DomainCertificateApplicationStatus.Denied or DomainCertificateApplicationStatus.Withdrawn)
        {
            throw new InvalidOperationException("This certificate application is already terminal.");
        }
        var updated = application with
        {
            Status = DomainCertificateApplicationStatus.Withdrawn,
            Decision = "Withdrawn by the applicant.",
            DecisionAtUtc = timeProvider.GetUtcNow(),
            Version = application.Version + 1
        };
        await repository.UpdateAsync(updated, application.Version, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    /// <summary>Records an authorized administrative decision for an application awaiting review.</summary>
    public async Task<ManagedDomainCertificateApplication> ReviewAsync(
        string reviewerId,
        string applicationId,
        bool approve,
        string? reviewerNotes,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(reviewerId, 256, nameof(reviewerId));
        ValidateIdentifier(applicationId, 128, nameof(applicationId));
        if (reviewerNotes is not null &&
            (string.IsNullOrWhiteSpace(reviewerNotes) || reviewerNotes.Length > 2_000 || reviewerNotes.Any(char.IsControl)))
        {
            throw new ArgumentException("Reviewer notes are invalid.", nameof(reviewerNotes));
        }

        var application = await repository.GetAsync(applicationId, cancellationToken).ConfigureAwait(false)
            ?? throw new DomainAccessDeniedException();
        if (application.Status != DomainCertificateApplicationStatus.PendingReview ||
            application.Eligibility?.Decision != DomainCertificatePolicyDecision.RequiresReview)
        {
            throw new InvalidOperationException("Only an application awaiting manual review can receive a review decision.");
        }

        var now = timeProvider.GetUtcNow();
        var updated = application with
        {
            Status = approve ? DomainCertificateApplicationStatus.Approved : DomainCertificateApplicationStatus.Rejected,
            ReviewerId = reviewerId,
            ReviewerNotes = reviewerNotes,
            Decision = approve ? "Approved after authorized manual review." : "Rejected after authorized manual review.",
            DecisionAtUtc = now,
            Version = application.Version + 1
        };
        await repository.UpdateAsync(updated, application.Version, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    private async Task<ManagedDomainCertificateApplication> RequireApplicationAsync(
        string actorId,
        string applicationId,
        CancellationToken cancellationToken)
    {
        ValidateIdentifier(applicationId, 128, nameof(applicationId));
        var application = await repository.GetAsync(applicationId, cancellationToken).ConfigureAwait(false);
        if (application is null) throw new DomainAccessDeniedException();
        _ = await RequireDomainAsync(actorId, application.DomainId, cancellationToken).ConfigureAwait(false);
        return application;
    }

    private async Task<ManagedDomainAccessView> RequireDomainAsync(string actorId, string domainId, CancellationToken cancellationToken)
    {
        var domain = await domainManagement.GetAsync(actorId, domainId, cancellationToken).ConfigureAwait(false);
        if (domain is null || !ManagedDomainAccessPolicy.CanManageSecurity(domain.AccessRole))
            throw new DomainAccessDeniedException();
        return domain;
    }

    private static void ValidateIdentifier(string value, int maximumLength, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
            throw new ArgumentException("A valid identifier is required.", parameterName);
    }
}

/// <summary>Thread-safe managed-domain application repository for focused tests and local composition.</summary>
public sealed class InMemoryManagedDomainCertificateApplicationRepository : IManagedDomainCertificateApplicationRepository
{
    private readonly ConcurrentDictionary<string, ManagedDomainCertificateApplication> applications = new(StringComparer.Ordinal);
    public Task<ManagedDomainCertificateApplication?> GetAsync(string applicationId, CancellationToken cancellationToken) =>
        Task.FromResult(applications.GetValueOrDefault(applicationId));
    public Task<IReadOnlyCollection<ManagedDomainCertificateApplication>> ListByDomainAsync(string domainId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<ManagedDomainCertificateApplication>>(
            applications.Values.Where(item => item.DomainId == domainId).OrderBy(item => item.CreatedAtUtc).ToArray());
    public Task AddAsync(ManagedDomainCertificateApplication application, CancellationToken cancellationToken)
    {
        if (!applications.TryAdd(application.ApplicationId, application)) throw new InvalidOperationException("Application already exists.");
        return Task.CompletedTask;
    }
    public Task UpdateAsync(ManagedDomainCertificateApplication application, long expectedVersion, CancellationToken cancellationToken)
    {
        if (!applications.TryGetValue(application.ApplicationId, out var current) || current.Version != expectedVersion ||
            !applications.TryUpdate(application.ApplicationId, application, current))
            throw new InvalidOperationException("The certificate application changed before the operation completed.");
        return Task.CompletedTask;
    }
}
