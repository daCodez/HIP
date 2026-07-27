using System.Security.Cryptography;
using System.Text;
using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

/// <summary>Owner-bound certificate and enrollment state required to authorize monitoring.</summary>
public sealed record DomainMonitoringEnrollmentState(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    DomainEnrollmentStatus EnrollmentStatus,
    DomainCertificateStatus CertificateStatus,
    DomainCertificateLevel CertificateLevel,
    DateTimeOffset? DnsVerifiedAtUtc,
    DateTimeOffset? WebsiteVerifiedAtUtc,
    DateTimeOffset? IdentityCompletedAtUtc,
    DateTimeOffset? MonitoringEnabledAtUtc,
    DateTimeOffset? LastMonitoringAtUtc,
    int? CurrentScore,
    DateTimeOffset? MonitoringNextCheckAtUtc = null,
    int MonitoringFailureCount = 0);

/// <summary>Audited owner opt-in that schedules immediate and recurring HIP monitoring.</summary>
public sealed record DomainMonitoringEnableRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    DateTimeOffset EnabledAtUtc,
    DateTimeOffset NextCheckAtUtc,
    string AuditEventId);

/// <summary>Privacy-safe result of one server-owned monitoring evaluation.</summary>
public sealed record DomainMonitoringCheckRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    DomainEnrollmentStatus ExpectedStatus,
    DomainEnrollmentStatus TargetStatus,
    int CurrentScore,
    int UnresolvedCriticalFindings,
    DateTimeOffset CheckedAtUtc,
    DateTimeOffset NextCheckAtUtc,
    string EvidenceDigest,
    string AuditEventId);

public enum DomainMonitoringWriteStatus
{
    Updated,
    Existing,
    NotFound,
    Conflict,
    Unavailable
}

/// <summary>Persistence boundary for monitoring opt-in, scheduling, and audited checks.</summary>
public interface IDomainCertificateMonitoringRepository
{
    Task<DomainMonitoringEnrollmentState?> GetForMonitoringAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken);

    Task<DomainMonitoringWriteStatus> TryEnableAsync(
        DomainMonitoringEnableRecord record,
        CancellationToken cancellationToken);

    Task<DomainMonitoringWriteStatus> TryApplyCheckAsync(
        DomainMonitoringCheckRecord record,
        CancellationToken cancellationToken);
}

public enum DomainCertificateMonitoringStartStatus
{
    NotFound,
    NotReady,
    EnabledPendingEvidence,
    Activated,
    Existing,
    Conflict,
    Unavailable
}

public sealed record DomainCertificateMonitoringStartResult(
    DomainCertificateMonitoringStartStatus Status,
    int? CurrentScore = null,
    DateTimeOffset? LastCheckedAtUtc = null);

public interface IDomainCertificateMonitoringService
{
    Task<DomainCertificateMonitoringStartResult> StartAsync(
        string ownerId,
        string domain,
        bool accountContactVerified,
        CancellationToken cancellationToken);
}

/// <summary>Enables monitoring for an active owner certificate and performs its first authoritative check.</summary>
public sealed class DomainCertificateMonitoringService(
    IDomainCertificateMonitoringRepository repository,
    IDomainCertificateSecurityScanService securityScanService,
    TimeProvider timeProvider) : IDomainCertificateMonitoringService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);

    public async Task<DomainCertificateMonitoringStartResult> StartAsync(
        string ownerId,
        string domain,
        bool accountContactVerified,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerId);
        var normalized = PublicLookup.DomainInputValidator.ValidateAndNormalize(domain);
        DomainMonitoringEnrollmentState? state;
        try
        {
            state = await repository.GetForMonitoringAsync(ownerId, normalized, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateMonitoringStartStatus.Unavailable);
        }

        if (state is null)
        {
            return Result(DomainCertificateMonitoringStartStatus.NotFound);
        }
        if (state.EnrollmentStatus is not DomainEnrollmentStatus.Verified and not DomainEnrollmentStatus.Monitored ||
            state.CertificateStatus != DomainCertificateStatus.Active ||
            state.CertificateLevel is not DomainCertificateLevel.Verified and not DomainCertificateLevel.Monitored ||
            state.DnsVerifiedAtUtc is null ||
            state.WebsiteVerifiedAtUtc is null ||
            state.IdentityCompletedAtUtc is null)
        {
            return Result(DomainCertificateMonitoringStartStatus.NotReady);
        }

        try
        {
            var now = timeProvider.GetUtcNow().ToUniversalTime();
            var enableWrite = await repository.TryEnableAsync(
                    new DomainMonitoringEnableRecord(
                        state.EnrollmentId,
                        ownerId,
                        normalized,
                        now,
                        now,
                        $"certificate-event:monitoring-enabled:{state.EnrollmentId}"),
                    cancellationToken)
                .ConfigureAwait(false);
            if (enableWrite is DomainMonitoringWriteStatus.NotFound)
            {
                return Result(DomainCertificateMonitoringStartStatus.NotFound);
            }
            if (enableWrite is DomainMonitoringWriteStatus.Conflict)
            {
                return Result(DomainCertificateMonitoringStartStatus.Conflict);
            }
            if (enableWrite is DomainMonitoringWriteStatus.Unavailable)
            {
                return Result(DomainCertificateMonitoringStartStatus.Unavailable);
            }

            var scan = await securityScanService.ScanAsync(
                    new DomainCertificateSecurityScanRequest(
                        normalized,
                        DomainCertificateLevel.Monitored,
                        accountContactVerified,
                        state.DnsVerifiedAtUtc,
                        state.DnsVerifiedAtUtc,
                        state.WebsiteVerifiedAtUtc,
                        IdentityInformationCompleted: true,
                        ContinuousMonitoringEnabled: true,
                        CertificateActive: true),
                    cancellationToken)
                .ConfigureAwait(false);
            if (scan.Status != DomainCertificateSecurityScanStatus.Evaluated ||
                scan.Scan is null ||
                scan.Evaluation is null)
            {
                return Result(DomainCertificateMonitoringStartStatus.EnabledPendingEvidence);
            }

            var target = scan.Evaluation.Decision == DomainCertificatePolicyDecision.Eligible
                ? DomainEnrollmentStatus.Monitored
                : DomainEnrollmentStatus.Verified;
            var checkedAt = scan.Evaluation.EvaluatedAtUtc;
            var digest = EvidenceDigest(scan);
            var checkWrite = await repository.TryApplyCheckAsync(
                    new DomainMonitoringCheckRecord(
                        state.EnrollmentId,
                        ownerId,
                        normalized,
                        state.EnrollmentStatus,
                        target,
                        scan.Scan.FinalHipScore,
                        CriticalFindingCount(scan.Evaluation),
                        checkedAt,
                        checkedAt.Add(CheckInterval),
                        digest,
                        $"certificate-event:monitoring-check:{digest[7..55]}"),
                    cancellationToken)
                .ConfigureAwait(false);
            if (checkWrite is DomainMonitoringWriteStatus.Conflict)
            {
                return Result(DomainCertificateMonitoringStartStatus.Conflict);
            }
            if (checkWrite is not DomainMonitoringWriteStatus.Updated and not DomainMonitoringWriteStatus.Existing)
            {
                return Result(DomainCertificateMonitoringStartStatus.Unavailable);
            }

            return new DomainCertificateMonitoringStartResult(
                target == DomainEnrollmentStatus.Monitored
                    ? DomainCertificateMonitoringStartStatus.Activated
                    : DomainCertificateMonitoringStartStatus.EnabledPendingEvidence,
                scan.Scan.FinalHipScore,
                checkedAt);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateMonitoringStartStatus.Unavailable);
        }
    }

    private static string EvidenceDigest(DomainCertificateSecurityScanResult scan)
    {
        var material = string.Join(
            '\n',
            scan.Scan!.ScanId,
            scan.Scan.Domain,
            scan.Scan.FinalHipScore,
            scan.Evaluation!.Decision,
            scan.Evaluation.EvaluatedAtUtc.ToString("O"),
            string.Join(',', scan.PublicFindingCodes ?? []));
        return $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant()}";
    }

    private static int CriticalFindingCount(DomainCertificatePolicyEvaluationResult evaluation) =>
        evaluation.Requirements.Count(item =>
            item.Status == DomainCertificateRequirementStatus.Missing &&
            item.Code == "security.no-critical-findings");

    private static DomainCertificateMonitoringStartResult Result(
        DomainCertificateMonitoringStartStatus status) => new(status);
}
