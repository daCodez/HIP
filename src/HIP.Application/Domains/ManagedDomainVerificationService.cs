using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Domain.Domains;
using HIP.Domain.Identity;

namespace HIP.Application.Domains;

/// <summary>Append-only, privacy-safe event for one managed-domain verification workflow.</summary>
public sealed record ManagedDomainVerificationAuditEvent(
    string EventId,
    string DomainId,
    VerificationMethod Method,
    string EventType,
    DomainVerificationAttemptOutcome Outcome,
    string TokenDigest,
    int ChallengeVersion,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset? ChallengeExpiresAtUtc);

/// <summary>Durable append-only boundary for managed-domain verification history.</summary>
public interface IManagedDomainVerificationAuditRepository
{
    /// <summary>Appends a verification event without storing the raw challenge token.</summary>
    Task AppendAsync(ManagedDomainVerificationAuditEvent auditEvent, CancellationToken cancellationToken);
    /// <summary>Lists one domain's verification history in occurrence order.</summary>
    Task<IReadOnlyCollection<ManagedDomainVerificationAuditEvent>> ListAsync(string domainId, CancellationToken cancellationToken);
}

/// <summary>Owner-safe verification challenge returned by managed-domain endpoints.</summary>
public sealed record ManagedDomainVerificationChallengeView(
    string DomainId,
    string DomainName,
    VerificationMethod Method,
    string Token,
    ManagedDomainVerificationStatus Status,
    int ChallengeVersion,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? VerifiedAtUtc);

/// <summary>Coordinates authorized managed-domain verification and its append-only audit history.</summary>
public sealed class ManagedDomainVerificationService(
    IDomainManagementService domainManagement,
    IDomainVerificationService verificationService,
    IManagedDomainVerificationAuditRepository auditRepository,
    TimeProvider timeProvider)
{
    /// <summary>Starts a challenge after confirming the actor can manage the stable domain record.</summary>
    public async Task<ManagedDomainVerificationChallengeView> StartAsync(
        string actorId,
        string domainId,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var domain = await RequireManageableAsync(actorId, domainId, cancellationToken).ConfigureAwait(false);
        var challenge = await verificationService.StartAsync(domain.DomainName, method, cancellationToken).ConfigureAwait(false);
        await domainManagement.UpdateVerificationAsync(
            actorId, domainId, ManagedDomainVerificationStatus.Pending, method, null, cancellationToken).ConfigureAwait(false);
        await AppendAsync(domainId, challenge, "challenge-started", DomainVerificationAttemptOutcome.Pending, cancellationToken)
            .ConfigureAwait(false);
        return View(domainId, challenge);
    }

    /// <summary>Checks live evidence and updates the domain only when the persisted challenge succeeds.</summary>
    public async Task<ManagedDomainVerificationChallengeView> CheckAsync(
        string actorId,
        string domainId,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var domain = await RequireManageableAsync(actorId, domainId, cancellationToken).ConfigureAwait(false);
        var retry = await verificationService.RetryAsync(domain.DomainName, method, cancellationToken).ConfigureAwait(false);
        var status = Map(retry.Request.Status);
        await domainManagement.UpdateVerificationAsync(
            actorId, domainId, status, method,
            status == ManagedDomainVerificationStatus.Verified ? retry.Request.VerifiedAtUtc : null,
            cancellationToken).ConfigureAwait(false);
        await AppendAsync(
            domainId,
            retry.Request,
            "verification-checked",
            retry.Request.LastAttemptOutcome ?? MapOutcome(retry.Request.Status),
            cancellationToken).ConfigureAwait(false);
        return View(domainId, retry.Request);
    }

    private async Task<ManagedDomainAccessView> RequireManageableAsync(
        string actorId,
        string domainId,
        CancellationToken cancellationToken)
    {
        var domain = await domainManagement.GetAsync(actorId, domainId, cancellationToken).ConfigureAwait(false);
        if (domain is null || !ManagedDomainAccessPolicy.CanManageSecurity(domain.AccessRole))
        {
            throw new DomainAccessDeniedException();
        }
        return domain;
    }

    private Task AppendAsync(
        string domainId,
        DomainVerificationRequest request,
        string eventType,
        DomainVerificationAttemptOutcome outcome,
        CancellationToken cancellationToken) =>
        auditRepository.AppendAsync(new ManagedDomainVerificationAuditEvent(
            $"domain-verification-event_{Guid.NewGuid():N}", domainId, request.Method, eventType, outcome,
            Digest(request.Token), request.ChallengeVersion, timeProvider.GetUtcNow(), request.ExpiresAtUtc), cancellationToken);

    private static ManagedDomainVerificationChallengeView View(string domainId, DomainVerificationRequest request) => new(
        domainId, request.Domain, request.Method, request.Token, Map(request.Status), request.ChallengeVersion,
        request.CreatedAtUtc, request.ExpiresAtUtc, request.VerifiedAtUtc);
    private static ManagedDomainVerificationStatus Map(VerificationStatus status) => status switch
    {
        VerificationStatus.Verified => ManagedDomainVerificationStatus.Verified,
        VerificationStatus.Expired => ManagedDomainVerificationStatus.Expired,
        VerificationStatus.Revoked => ManagedDomainVerificationStatus.Revoked,
        _ => ManagedDomainVerificationStatus.Pending
    };
    private static DomainVerificationAttemptOutcome MapOutcome(VerificationStatus status) => status switch
    {
        VerificationStatus.Verified => DomainVerificationAttemptOutcome.Succeeded,
        VerificationStatus.Pending => DomainVerificationAttemptOutcome.Pending,
        _ => DomainVerificationAttemptOutcome.Failed
    };
    private static string Digest(string token) =>
        $"sha256:{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)))}";
}

/// <summary>Thread-safe verification audit store for focused tests and local composition.</summary>
public sealed class InMemoryManagedDomainVerificationAuditRepository : IManagedDomainVerificationAuditRepository
{
    private readonly ConcurrentQueue<ManagedDomainVerificationAuditEvent> events = new();
    public IReadOnlyList<ManagedDomainVerificationAuditEvent> Events => events.ToArray();
    public Task AppendAsync(ManagedDomainVerificationAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        events.Enqueue(auditEvent);
        return Task.CompletedTask;
    }
    public Task<IReadOnlyCollection<ManagedDomainVerificationAuditEvent>> ListAsync(string domainId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<ManagedDomainVerificationAuditEvent>>(
            events.Where(item => item.DomainId == domainId).OrderBy(item => item.OccurredAtUtc).ToArray());
}
