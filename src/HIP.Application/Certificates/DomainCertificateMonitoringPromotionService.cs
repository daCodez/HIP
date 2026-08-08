using System.Security.Cryptography;
using System.Text;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

/// <summary>
/// Reissues a Verified certificate as Monitored only after fresh server-owned evidence satisfies policy.
/// </summary>
public sealed class DomainCertificateMonitoringPromotionService(
    IDomainCertificateRepository certificateRepository,
    IDomainCertificateMonitoringRepository monitoringRepository,
    IDomainCertificateSigningService signingService,
    ICanonicalJsonService canonicalJsonService,
    DomainCertificatePublicEndpointOptions endpointOptions,
    DomainCertificateSigningAuthorityPolicy signingAuthorityPolicy)
    : IDomainCertificateMonitoringPromotionService
{
    public async Task<DomainCertificateMonitoringPromotionResult> PromoteAsync(
        DomainMonitoringEnrollmentState state,
        DomainCertificateSecurityScanResult scan,
        DomainMonitoringCheckRecord check,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsEligible(state, scan, check))
        {
            return Result(DomainCertificateMonitoringPromotionStatus.Conflict);
        }

        HipStoredDomainCertificate? current;
        try
        {
            current = await certificateRepository.GetCurrentByDomainAsync(state.Domain, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateMonitoringPromotionStatus.Unavailable);
        }

        if (!MatchesCurrent(state, current))
        {
            return Result(DomainCertificateMonitoringPromotionStatus.Conflict);
        }

        var origin = ValidatedPublicOrigin(endpointOptions.PublicOrigin);
        if (current!.Certificate.Payload.Level == DomainCertificateLevel.Monitored &&
            IsSignedByAuthorizedAuthority(current.Certificate, signingAuthorityPolicy) &&
            HasCurrentPublicEndpoints(current.Certificate.Payload, origin))
        {
            var refresh = await monitoringRepository.TryApplyCheckAsync(check, cancellationToken)
                .ConfigureAwait(false);
            return Result(refresh is DomainMonitoringWriteStatus.Updated or DomainMonitoringWriteStatus.Existing
                ? DomainCertificateMonitoringPromotionStatus.Existing
                : refresh == DomainMonitoringWriteStatus.Unavailable
                    ? DomainCertificateMonitoringPromotionStatus.Unavailable
                    : DomainCertificateMonitoringPromotionStatus.Conflict);
        }

        var payload = current.Certificate.Payload;
        var certificateId = NextCertificateId(state.EnrollmentId, state.Domain, payload.CertificateVersion + 1);
        var draft = new DomainCertificateSigningDraft(
            certificateId,
            payload.CertificateVersion + 1,
            state.Domain,
            DomainCertificateLevel.Monitored,
            payload.PublicDisplayName,
            payload.PublicOrganizationName,
            payload.RegistrantPublicKeyId,
            payload.CompletedVerificationMethods,
            scan.PublicRiskClassification,
            scan.PublicFindingCodes ?? [],
            $"{origin}/api/v1/public/certificates/{certificateId}",
            $"{origin}/certificate/{certificateId}",
            payload.LastVerificationAtUtc,
            check.CheckedAtUtc,
            scan.Evaluation!);

        DomainCertificateSigningResult signing;
        try
        {
            signing = await signingService.SignAsync(draft, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateMonitoringPromotionStatus.Unavailable);
        }
        if (signing.Status != DomainCertificateSigningStatus.Signed || signing.Certificate is null)
        {
            return Result(signing.Status is DomainCertificateSigningStatus.SignerUnavailable
                or DomainCertificateSigningStatus.VerificationFailed
                    ? DomainCertificateMonitoringPromotionStatus.Unavailable
                    : DomainCertificateMonitoringPromotionStatus.Conflict);
        }

        HipStoredDomainCertificate stored;
        try
        {
            stored = DomainCertificateIssuanceService.CreateStored(
                new DomainCertificateIssuanceRequest(
                    state.EnrollmentId,
                    state.OwnerId,
                    "hip-monitoring-service",
                    draft),
                signing.Certificate,
                canonicalJsonService);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return Result(DomainCertificateMonitoringPromotionStatus.Conflict);
        }

        DomainMonitoringWriteStatus write;
        try
        {
            write = await monitoringRepository.TryApplyPromotedCheckAsync(
                    new DomainMonitoringCertificatePromotionRecord(
                        check,
                        payload.CertificateId,
                        payload.CertificateVersion,
                        stored),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateMonitoringPromotionStatus.Unavailable);
        }

        return write switch
        {
            DomainMonitoringWriteStatus.Updated => new(
                DomainCertificateMonitoringPromotionStatus.Promoted,
                signing.Certificate),
            DomainMonitoringWriteStatus.Existing => new(
                DomainCertificateMonitoringPromotionStatus.Existing,
                signing.Certificate),
            DomainMonitoringWriteStatus.Unavailable => Result(
                DomainCertificateMonitoringPromotionStatus.Unavailable),
            _ => Result(DomainCertificateMonitoringPromotionStatus.Conflict)
        };
    }

    private static bool IsEligible(
        DomainMonitoringEnrollmentState state,
        DomainCertificateSecurityScanResult scan,
        DomainMonitoringCheckRecord check) =>
        state is not null && scan is not null && check is not null &&
        scan.Status == DomainCertificateSecurityScanStatus.Evaluated &&
        scan.Scan is not null && scan.Evaluation is not null &&
        scan.Evaluation.Decision == DomainCertificatePolicyDecision.Eligible &&
        scan.Evaluation.RequestedLevel == DomainCertificateLevel.Monitored &&
        scan.Evaluation.Domain == state.Domain && scan.Scan.Domain == state.Domain &&
        check.EnrollmentId == state.EnrollmentId && check.OwnerId == state.OwnerId &&
        check.Domain == state.Domain && check.ExpectedStatus == state.EnrollmentStatus &&
        check.TargetStatus == DomainEnrollmentStatus.Monitored &&
        check.CheckedAtUtc == scan.Evaluation.EvaluatedAtUtc &&
        check.CurrentScore == scan.Scan.FinalHipScore &&
        check.UnresolvedCriticalFindings == 0;

    private static bool MatchesCurrent(
        DomainMonitoringEnrollmentState state,
        HipStoredDomainCertificate? current) =>
        current is not null && current.EnrollmentId == state.EnrollmentId &&
        current.OwnerId == state.OwnerId && current.CurrentStatus == DomainCertificateStatus.Active &&
        current.Certificate.Payload.Domain == state.Domain &&
        current.Certificate.Payload.Status == DomainCertificateStatus.Active &&
        current.Certificate.Payload.Level == state.CertificateLevel &&
        current.Certificate.Payload.Level is DomainCertificateLevel.Verified or DomainCertificateLevel.Monitored;

    private static bool IsSignedByAuthorizedAuthority(
        SignedDomainTrustCertificate certificate,
        DomainCertificateSigningAuthorityPolicy signingAuthorityPolicy) =>
        signingAuthorityPolicy.IsAuthorized(
            certificate.Signature.AuthorityId,
            certificate.Signature.KeyId);

    private static bool HasCurrentPublicEndpoints(DomainTrustCertificatePayload payload, string origin) =>
        payload.RevocationStatusUrl == $"{origin}/api/v1/public/certificates/{payload.CertificateId}" &&
        payload.PublicCertificateUrl == $"{origin}/certificate/{payload.CertificateId}";

    private static string NextCertificateId(string enrollmentId, string domain, int version)
    {
        var digest = Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{enrollmentId}\n{domain}\n{DomainCertificatePolicy.V1.Version}\n{version}")));
        return $"hip-domain-cert-v1-{digest[..40]}-v{version}";
    }

    private static string ValidatedPublicOrigin(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            uri.Port != 443 || !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException("The certificate public origin must be an HTTPS origin on port 443.");
        }
        return value.TrimEnd('/');
    }

    private static DomainCertificateMonitoringPromotionResult Result(
        DomainCertificateMonitoringPromotionStatus status) => new(status);
}
