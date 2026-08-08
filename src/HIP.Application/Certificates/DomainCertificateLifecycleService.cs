using System.Security.Cryptography;
using System.Text;
using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

/// <summary>Validated atomic live-status transition and permanent audit event.</summary>
public sealed record DomainCertificateStatusTransition(
    string CertificateId,
    DomainCertificateStatus ExpectedStatus,
    DomainCertificateStatus TargetStatus,
    string ActorId,
    string ReasonCode,
    string PublicSummary,
    DateTimeOffset OccurredAtUtc,
    string EventId);

public enum DomainCertificateTransitionWriteStatus
{
    Updated,
    ExistingSame,
    NotFound,
    Conflict
}

public sealed record DomainCertificateTransitionWriteResult(DomainCertificateTransitionWriteStatus Status);

public interface IDomainCertificateLifecycleRepository
{
    Task<DomainCertificateTransitionWriteResult> TryTransitionStatusAsync(
        DomainCertificateStatusTransition transition,
        CancellationToken cancellationToken);
}

public sealed record DomainCertificateLifecycleRequest(
    string CertificateId,
    DomainCertificateStatus TargetStatus,
    string Reason,
    string OperationId,
    string ActorId);

public enum DomainCertificateLifecycleChangeStatus
{
    InvalidRequest,
    NotFound,
    Conflict,
    Unavailable,
    Changed,
    Existing
}

public sealed record DomainCertificateLifecycleChangeResult(
    DomainCertificateLifecycleChangeStatus Status,
    DomainCertificateStatus? CurrentStatus = null);

public interface IDomainCertificateLifecycleService
{
    Task<DomainCertificateLifecycleChangeResult> ChangeStatusAsync(
        DomainCertificateLifecycleRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Validates and records authorized certificate suspension, reinstatement, and revocation.</summary>
public sealed class DomainCertificateLifecycleService(
    IDomainCertificateRepository certificateRepository,
    IDomainCertificateLifecycleRepository lifecycleRepository,
    TimeProvider timeProvider) : IDomainCertificateLifecycleService
{
    public async Task<DomainCertificateLifecycleChangeResult> ChangeStatusAsync(
        DomainCertificateLifecycleRequest request,
        CancellationToken cancellationToken)
    {
        string reason;
        try
        {
            ArgumentNullException.ThrowIfNull(request);
            ValidateIdentifier(request.CertificateId, 128);
            ValidateIdentifier(request.ActorId, 256);
            ValidateIdentifier(request.OperationId, 128);
            reason = request.Reason?.Trim() ?? string.Empty;
            if (reason.Length is < 5 or > 500 || reason.Any(char.IsControl) ||
                request.TargetStatus is not (DomainCertificateStatus.ActionRequired or DomainCertificateStatus.Suspended or DomainCertificateStatus.Active or DomainCertificateStatus.Revoked))
            {
                return Result(DomainCertificateLifecycleChangeStatus.InvalidRequest);
            }
            DomainCertificateLifecycle.RequireReason(request.TargetStatus, reason);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return Result(DomainCertificateLifecycleChangeStatus.InvalidRequest);
        }

        HipStoredDomainCertificate? stored;
        try
        {
            stored = await certificateRepository.GetByIdAsync(request.CertificateId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateLifecycleChangeStatus.Unavailable);
        }
        if (stored is null)
        {
            return Result(DomainCertificateLifecycleChangeStatus.NotFound);
        }
        if (stored.CurrentStatus == request.TargetStatus)
        {
            return new DomainCertificateLifecycleChangeResult(DomainCertificateLifecycleChangeStatus.Existing, stored.CurrentStatus);
        }
        try
        {
            DomainCertificateLifecycle.RequireTransition(stored.CurrentStatus, request.TargetStatus);
        }
        catch (InvalidOperationException)
        {
            return new DomainCertificateLifecycleChangeResult(DomainCertificateLifecycleChangeStatus.Conflict, stored.CurrentStatus);
        }

        var transition = new DomainCertificateStatusTransition(
            request.CertificateId,
            stored.CurrentStatus,
            request.TargetStatus,
            request.ActorId,
            ReasonCode(request.TargetStatus),
            reason,
            timeProvider.GetUtcNow(),
            $"certificate-event:{Digest(request.OperationId)}");
        DomainCertificateTransitionWriteResult write;
        try
        {
            write = await lifecycleRepository.TryTransitionStatusAsync(transition, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateLifecycleChangeStatus.Unavailable);
        }
        return write.Status switch
        {
            DomainCertificateTransitionWriteStatus.Updated => new(DomainCertificateLifecycleChangeStatus.Changed, request.TargetStatus),
            DomainCertificateTransitionWriteStatus.ExistingSame => new(DomainCertificateLifecycleChangeStatus.Existing, request.TargetStatus),
            DomainCertificateTransitionWriteStatus.NotFound => Result(DomainCertificateLifecycleChangeStatus.NotFound),
            _ => Result(DomainCertificateLifecycleChangeStatus.Conflict)
        };
    }

    private static string ReasonCode(DomainCertificateStatus target) => target switch
    {
        DomainCertificateStatus.Suspended => "manual-suspension",
        DomainCertificateStatus.Revoked => "manual-revocation",
        DomainCertificateStatus.ActionRequired => "action-required",
        _ => "manual-reinstatement"
    };

    private static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void ValidateIdentifier(string value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("Certificate lifecycle identifier is invalid.");
        }
    }

    private static DomainCertificateLifecycleChangeResult Result(DomainCertificateLifecycleChangeStatus status) => new(status);
}
