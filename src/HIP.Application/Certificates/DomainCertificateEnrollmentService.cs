using System.Security.Cryptography;
using System.Text;
using HIP.Application.Identity;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;

namespace HIP.Application.Certificates;

/// <summary>Owner request to begin one domain-control and certificate enrollment.</summary>
public sealed record DomainCertificateEnrollmentStartRequest(
    string Domain,
    string DisplayName,
    VerificationMethod VerificationMethod);

/// <summary>Safe result of an owner enrollment command.</summary>
public enum DomainCertificateEnrollmentStartStatus
{
    InvalidRequest,
    Conflict,
    PersistenceUnavailable,
    Started,
    Existing
}

/// <summary>Owner-safe challenge response that never includes signing private key material.</summary>
public sealed record DomainCertificateEnrollmentStartResult(
    DomainCertificateEnrollmentStartStatus Status,
    string? Domain = null,
    VerificationMethod? VerificationMethod = null,
    string? ChallengeToken = null,
    DateTimeOffset? ChallengeExpiresAtUtc = null);

/// <summary>Safe outcome of checking HIP's stored DNS challenge.</summary>
public enum DomainCertificateDnsCheckStatus
{
    InvalidRequest,
    NotFound,
    Pending,
    Verified,
    Conflict,
    Unavailable
}

/// <summary>DNS check result without returning the stored challenge token.</summary>
public sealed record DomainCertificateDnsCheckResult(
    DomainCertificateDnsCheckStatus Status,
    DateTimeOffset? VerifiedAtUtc = null);

/// <summary>Safe outcome of preparing the fixed HTTPS website-control challenge.</summary>
public enum DomainCertificateWebsitePrepareStatus
{
    InvalidRequest,
    NotFound,
    NotReady,
    Ready,
    Unavailable
}

/// <summary>Owner-downloadable public challenge document; it contains no private key or account data.</summary>
public sealed record DomainCertificateWebsitePrepareResult(
    DomainCertificateWebsitePrepareStatus Status,
    HipWellKnownDocument? Document = null);

/// <summary>Safe outcome of checking challenge-bound HTTPS website control.</summary>
public enum DomainCertificateWebsiteCheckStatus
{
    InvalidRequest,
    NotFound,
    NotReady,
    Pending,
    Verified,
    Conflict,
    Unavailable
}

public sealed record DomainCertificateWebsiteCheckResult(
    DomainCertificateWebsiteCheckStatus Status,
    DateTimeOffset? VerifiedAtUtc = null);

/// <summary>Owner-supplied identity fields with explicit public disclosure choices.</summary>
public sealed record DomainCertificateIdentityProfileRequest(
    string PublicDisplayName,
    string? OrganizationName,
    string? PublicWebsiteContact,
    string SecurityContact,
    string? CountryOrRegion,
    bool PublishOrganization,
    bool PublishCountryOrRegion);

public enum DomainCertificateIdentityProfileStatus
{
    InvalidRequest,
    NotFound,
    NotReady,
    Conflict,
    Completed,
    Existing,
    Unavailable
}

public sealed record DomainCertificateIdentityProfileResult(DomainCertificateIdentityProfileStatus Status);

/// <summary>Owner-authorized facade for starting formal domain certificate enrollment.</summary>
public interface IDomainCertificateEnrollmentService
{
    Task<DomainCertificateEnrollmentStartResult> StartAsync(
        string ownerId,
        DomainCertificateEnrollmentStartRequest request,
        CancellationToken cancellationToken);
    Task<DomainCertificateEnrollmentStartResult> StartAsync(
        string ownerId,
        string websiteOwnerActorId,
        DomainCertificateEnrollmentStartRequest request,
        CancellationToken cancellationToken);

    Task<DomainCertificateDnsCheckResult> CheckDnsAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken);
    Task<DomainCertificateDnsCheckResult> CheckDnsAsync(
        string ownerId,
        string websiteOwnerActorId,
        string domain,
        CancellationToken cancellationToken);

    Task<DomainCertificateWebsitePrepareResult> PrepareWebsiteVerificationAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken);
    Task<DomainCertificateWebsitePrepareResult> PrepareWebsiteVerificationAsync(
        string ownerId,
        string websiteOwnerActorId,
        string domain,
        CancellationToken cancellationToken);

    Task<DomainCertificateWebsiteCheckResult> CheckWebsiteAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken);
    Task<DomainCertificateWebsiteCheckResult> CheckWebsiteAsync(
        string ownerId,
        string websiteOwnerActorId,
        string domain,
        CancellationToken cancellationToken);

    Task<DomainCertificateIdentityProfileResult> CompleteIdentityProfileAsync(
        string ownerId,
        string domain,
        DomainCertificateIdentityProfileRequest request,
        CancellationToken cancellationToken);
}


/// <summary>Reuses website identity verification and atomically records certificate enrollment.</summary>
public sealed class DomainCertificateEnrollmentService(
    DomainRegistrationNormalizer normalizer,
    IWebsiteIdentityService websiteIdentityService,
    IDomainEnrollmentRepository enrollmentRepository,
    IDomainVerificationService domainVerificationService,
    IDomainVerificationRequestRepository verificationRequests,
    IWellKnownHipDocumentFetcher wellKnownFetcher,
    DomainCertificatePolicy policy,
    TimeProvider timeProvider,
    DomainVerificationLifecycleOptions? lifecycleOptions = null) : IDomainCertificateEnrollmentService
{
    private readonly DomainVerificationLifecycleOptions verificationLifecycle =
        (lifecycleOptions ?? DomainVerificationLifecycleOptions.Default).Validate();

    public Task<DomainCertificateEnrollmentStartResult> StartAsync(
        string ownerId,
        DomainCertificateEnrollmentStartRequest request,
        CancellationToken cancellationToken) =>
        StartAsync(ownerId, ownerId, request, cancellationToken);

    /// <summary>Starts enrollment while keeping account storage scope separate from the authenticated website owner actor.</summary>
    public async Task<DomainCertificateEnrollmentStartResult> StartAsync(
        string ownerId,
        string websiteOwnerActorId,
        DomainCertificateEnrollmentStartRequest request,
        CancellationToken cancellationToken)
    {
        string domain;
        string displayName;
        try
        {
            ValidateIdentifier(ownerId, 256);
            ValidateIdentifier(websiteOwnerActorId, 256);
            ArgumentNullException.ThrowIfNull(request);
            domain = normalizer.Normalize(request.Domain);
            displayName = request.DisplayName?.Trim() ?? string.Empty;
            if (displayName.Length is < 1 or > 200 || displayName.Any(char.IsControl) ||
                request.VerificationMethod != VerificationMethod.DnsTxt)
            {
                return Result(DomainCertificateEnrollmentStartStatus.InvalidRequest);
            }
        }
        catch (ArgumentException)
        {
            return Result(DomainCertificateEnrollmentStartStatus.InvalidRequest);
        }

        WebsiteIdentityRegistrationResponse website;
        try
        {
            website = await websiteIdentityService.RegisterAsync(
                new WebsiteIdentityRegistrationRequest(domain, displayName, request.VerificationMethod),
                websiteOwnerActorId,
                "Consumer",
                cancellationToken).ConfigureAwait(false);
        }
        catch (WebsiteIdentityRegistrationConflictException)
        {
            return Result(DomainCertificateEnrollmentStartStatus.Conflict);
        }
        catch (ArgumentException)
        {
            return Result(DomainCertificateEnrollmentStartStatus.InvalidRequest);
        }

        var now = timeProvider.GetUtcNow();
        var identity = Digest($"{ownerId}\n{domain}");
        var start = new DomainEnrollmentStartRecord(
            $"hip-enrollment-{identity}",
            ownerId,
            domain,
            DomainEnrollmentStatus.PendingOwnership,
            policy.Validate().Version,
            now,
            $"certificate-event:{Digest($"enrollment-start\n{identity}")}");
        DomainEnrollmentRepositoryWriteResult write;
        try
        {
            write = await enrollmentRepository.TryStartEnrollmentAsync(start, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateEnrollmentStartStatus.PersistenceUnavailable);
        }

        var status = write.Status switch
        {
            DomainEnrollmentRepositoryWriteStatus.Created => DomainCertificateEnrollmentStartStatus.Started,
            DomainEnrollmentRepositoryWriteStatus.ExistingSame => DomainCertificateEnrollmentStartStatus.Existing,
            _ => DomainCertificateEnrollmentStartStatus.Conflict
        };
        return new DomainCertificateEnrollmentStartResult(
            status,
            domain,
            website.VerificationRequest.Method,
            website.VerificationRequest.Token,
            website.VerificationRequest.ExpiresAtUtc);
    }

    public Task<DomainCertificateDnsCheckResult> CheckDnsAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken) =>
        CheckDnsAsync(ownerId, ownerId, domain, cancellationToken);

    /// <summary>Checks DNS for an account enrollment using the authenticated website owner actor.</summary>
    public async Task<DomainCertificateDnsCheckResult> CheckDnsAsync(
        string ownerId,
        string websiteOwnerActorId,
        string domain,
        CancellationToken cancellationToken)
    {
        string normalized;
        try
        {
            ValidateIdentifier(ownerId, 256);
            ValidateIdentifier(websiteOwnerActorId, 256);
            normalized = normalizer.Normalize(domain);
        }
        catch (ArgumentException)
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.InvalidRequest);
        }

        WebsiteIdentity? website;
        try
        {
            website = await websiteIdentityService.GetAsync(
                normalized,
                websiteOwnerActorId,
                "Consumer",
                cancellationToken).ConfigureAwait(false);
        }
        catch (WebsiteIdentityRegistrationConflictException)
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.NotFound);
        }
        if (website is null || website.PreferredVerificationMethod != VerificationMethod.DnsTxt)
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.NotFound);
        }

        DomainVerificationRequest? challenge;
        try
        {
            challenge = await domainVerificationService.GetAsync(
                normalized,
                VerificationMethod.DnsTxt,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.Unavailable);
        }
        if (challenge is null)
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.NotFound);
        }

        WebsiteIdentity verified;
        try
        {
            verified = await websiteIdentityService.VerifyAsync(
                new WebsiteVerificationRequest(normalized, VerificationMethod.DnsTxt, challenge.Token),
                websiteOwnerActorId,
                "Consumer",
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.Unavailable);
        }
        if (verified.VerificationStatus != VerificationStatus.Verified || verified.VerifiedAtUtc is null)
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.Pending);
        }

        var identity = Digest($"{ownerId}\n{normalized}");
        DomainEnrollmentTransitionWriteResult write;
        try
        {
            write = await enrollmentRepository.TryApplyOwnershipVerificationAsync(
                new DomainOwnershipVerificationRecord(
                    $"hip-enrollment-{identity}",
                    ownerId,
                    normalized,
                    VerificationMethod.DnsTxt,
                    verified.VerifiedAtUtc.Value,
                    $"certificate-event:{Digest($"ownership-verified\n{identity}")}"),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.Unavailable);
        }
        return write.Status switch
        {
            DomainEnrollmentTransitionWriteStatus.Updated or
            DomainEnrollmentTransitionWriteStatus.AlreadyApplied =>
                new DomainCertificateDnsCheckResult(
                    DomainCertificateDnsCheckStatus.Verified,
                    verified.VerifiedAtUtc),
            DomainEnrollmentTransitionWriteStatus.NotFound =>
                new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.NotFound),
            _ => new DomainCertificateDnsCheckResult(DomainCertificateDnsCheckStatus.Conflict)
        };
    }

    public Task<DomainCertificateWebsitePrepareResult> PrepareWebsiteVerificationAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken) =>
        PrepareWebsiteVerificationAsync(ownerId, ownerId, domain, cancellationToken);

    /// <summary>Prepares website verification using the authenticated website owner actor.</summary>
    public async Task<DomainCertificateWebsitePrepareResult> PrepareWebsiteVerificationAsync(
        string ownerId,
        string websiteOwnerActorId,
        string domain,
        CancellationToken cancellationToken)
    {
        string normalized;
        try
        {
            ValidateIdentifier(ownerId, 256);
            ValidateIdentifier(websiteOwnerActorId, 256);
            normalized = normalizer.Normalize(domain);
        }
        catch (ArgumentException)
        {
            return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.InvalidRequest);
        }

        try
        {
            var enrollment = await enrollmentRepository.GetCurrentAsync(ownerId, normalized, cancellationToken).ConfigureAwait(false);
            if (enrollment is null)
            {
                return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.NotFound);
            }
            if (enrollment.Status != DomainEnrollmentStatus.OwnershipVerified || enrollment.DnsVerifiedAtUtc is null)
            {
                return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.NotReady);
            }

            var website = await websiteIdentityService.GetAsync(normalized, websiteOwnerActorId, "Consumer", cancellationToken).ConfigureAwait(false);
            if (website is null || website.VerificationStatus != VerificationStatus.Verified)
            {
                return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.NotReady);
            }

            var challenge = await domainVerificationService.GetOrStartAsync(
                normalized,
                VerificationMethod.WellKnownHipJson,
                cancellationToken).ConfigureAwait(false);
            if (challenge.Status is VerificationStatus.Revoked or VerificationStatus.Expired or VerificationStatus.Suspended ||
                challenge.VerificationAttemptCount >= verificationLifecycle.MaximumVerificationAttempts ||
                challenge.ExpiresAtUtc is null || challenge.ExpiresAtUtc <= timeProvider.GetUtcNow())
            {
                return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.NotReady);
            }

            var document = new HipWellKnownDocument(
                normalized,
                website.HipIdentityId,
                website.PublicKeys,
                timeProvider.GetUtcNow(),
                SchemaVersion: "1",
                VerificationChallenge: challenge.Token,
                ExpiresAtUtc: challenge.ExpiresAtUtc);
            return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.Ready, document);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (WebsiteIdentityRegistrationConflictException)
        {
            return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.NotFound);
        }
        catch
        {
            return new DomainCertificateWebsitePrepareResult(DomainCertificateWebsitePrepareStatus.Unavailable);
        }
    }

    public Task<DomainCertificateWebsiteCheckResult> CheckWebsiteAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken) =>
        CheckWebsiteAsync(ownerId, ownerId, domain, cancellationToken);

    /// <summary>Checks website control using the authenticated website owner actor.</summary>
    public async Task<DomainCertificateWebsiteCheckResult> CheckWebsiteAsync(
        string ownerId,
        string websiteOwnerActorId,
        string domain,
        CancellationToken cancellationToken)
    {
        string normalized;
        try
        {
            ValidateIdentifier(ownerId, 256);
            ValidateIdentifier(websiteOwnerActorId, 256);
            normalized = normalizer.Normalize(domain);
        }
        catch (ArgumentException)
        {
            return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.InvalidRequest);
        }

        try
        {
            var enrollment = await enrollmentRepository.GetCurrentAsync(ownerId, normalized, cancellationToken).ConfigureAwait(false);
            if (enrollment is null)
            {
                return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.NotFound);
            }
            if (enrollment.WebsiteVerifiedAtUtc is { } existingVerifiedAt)
            {
                return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.Verified, existingVerifiedAt);
            }
            if (enrollment.Status != DomainEnrollmentStatus.OwnershipVerified || enrollment.DnsVerifiedAtUtc is null)
            {
                return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.NotReady);
            }

            var website = await websiteIdentityService.GetAsync(normalized, websiteOwnerActorId, "Consumer", cancellationToken).ConfigureAwait(false);
            var challenge = await domainVerificationService.GetAsync(
                normalized,
                VerificationMethod.WellKnownHipJson,
                cancellationToken).ConfigureAwait(false);
            if (website is null || website.VerificationStatus != VerificationStatus.Verified || challenge is null)
            {
                return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.NotReady);
            }

            var now = timeProvider.GetUtcNow();
            if (challenge.ExpiresAtUtc is null || challenge.ExpiresAtUtc <= now ||
                challenge.Status is VerificationStatus.Revoked or VerificationStatus.Expired or VerificationStatus.Suspended ||
                challenge.VerificationAttemptCount >= verificationLifecycle.MaximumVerificationAttempts)
            {
                return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.NotReady);
            }

            var document = await wellKnownFetcher.FetchAsync(normalized, cancellationToken).ConfigureAwait(false);
            if (!MatchesWebsiteChallenge(document, website, challenge, now))
            {
                var attemptCount = checked(challenge.VerificationAttemptCount + 1);
                var failed = challenge with
                {
                    Status = attemptCount >= verificationLifecycle.MaximumVerificationAttempts
                        ? VerificationStatus.Suspended
                        : VerificationStatus.Unverified,
                    LastCheckedAtUtc = now,
                    LastCheckMessage = attemptCount >= verificationLifecycle.MaximumVerificationAttempts
                        ? "The website verification attempt limit was reached; regenerate the challenge before retrying."
                        : "The fixed HTTPS well-known document did not match the active challenge.",
                    VerificationAttemptCount = attemptCount,
                    LastAttemptOutcome = DomainVerificationAttemptOutcome.Failed
                };
                if (!await verificationRequests.TryUpdateAsync(challenge, failed, cancellationToken).ConfigureAwait(false))
                {
                    return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.Conflict);
                }
                return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.Pending);
            }

            var verifiedAt = challenge.VerifiedAtUtc ?? now;
            if (challenge.Status != VerificationStatus.Verified)
            {
                var consumed = challenge with
                {
                    Status = VerificationStatus.Verified,
                    VerifiedAtUtc = verifiedAt,
                    LastCheckedAtUtc = now,
                    LastCheckMessage = "HIP verified the challenge-bound document at the fixed HTTPS well-known path.",
                    VerificationAttemptCount = checked(challenge.VerificationAttemptCount + 1),
                    ConsumedAtUtc = now,
                    LastAttemptOutcome = DomainVerificationAttemptOutcome.Succeeded
                };
                if (!await verificationRequests.TryUpdateAsync(challenge, consumed, cancellationToken).ConfigureAwait(false))
                {
                    var current = await verificationRequests.GetAsync(normalized, VerificationMethod.WellKnownHipJson, cancellationToken).ConfigureAwait(false);
                    if (current?.Status != VerificationStatus.Verified || current.VerifiedAtUtc is null)
                    {
                        return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.Conflict);
                    }
                    verifiedAt = current.VerifiedAtUtc.Value;
                }
            }

            var identity = Digest($"{ownerId}\n{normalized}");
            var write = await enrollmentRepository.TryApplyWebsiteVerificationAsync(
                new DomainWebsiteVerificationRecord(
                    enrollment.EnrollmentId,
                    ownerId,
                    normalized,
                    VerificationMethod.WellKnownHipJson,
                    verifiedAt,
                    $"certificate-event:{Digest($"website-verified\n{identity}")}"),
                cancellationToken).ConfigureAwait(false);
            return write.Status switch
            {
                DomainEnrollmentTransitionWriteStatus.Updated or DomainEnrollmentTransitionWriteStatus.AlreadyApplied =>
                    new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.Verified, verifiedAt),
                DomainEnrollmentTransitionWriteStatus.NotFound =>
                    new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.NotFound),
                _ => new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.Conflict)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (WebsiteIdentityRegistrationConflictException)
        {
            return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.NotFound);
        }
        catch
        {
            return new DomainCertificateWebsiteCheckResult(DomainCertificateWebsiteCheckStatus.Unavailable);
        }
    }

    private static bool MatchesWebsiteChallenge(
        HipWellKnownDocument? document,
        WebsiteIdentity website,
        DomainVerificationRequest challenge,
        DateTimeOffset now)
    {
        if (document is null || document.SchemaVersion != "1" || document.Domain != website.Domain ||
            document.HipIdentityId != website.HipIdentityId || document.ExpiresAtUtc is null ||
            document.ExpiresAtUtc <= now || document.ExpiresAtUtc > challenge.ExpiresAtUtc ||
            document.IssuedAtUtc < challenge.CreatedAtUtc || document.IssuedAtUtc > now.AddMinutes(5) ||
            document.VerificationChallenge is null)
        {
            return false;
        }

        var tokenMatches = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(document.VerificationChallenge),
            Encoding.UTF8.GetBytes(challenge.Token));
        var documentKeys = document.PublicKeys.OrderBy(key => key.KeyId, StringComparer.Ordinal).ToArray();
        var websiteKeys = website.PublicKeys.OrderBy(key => key.KeyId, StringComparer.Ordinal).ToArray();
        return tokenMatches && documentKeys.SequenceEqual(websiteKeys);
    }

    public async Task<DomainCertificateIdentityProfileResult> CompleteIdentityProfileAsync(
        string ownerId,
        string domain,
        DomainCertificateIdentityProfileRequest request,
        CancellationToken cancellationToken)
    {
        string normalized;
        string displayName;
        string? organization;
        string? publicContact;
        string securityContact;
        string? country;
        try
        {
            ValidateIdentifier(ownerId, 256);
            ArgumentNullException.ThrowIfNull(request);
            normalized = normalizer.Normalize(domain);
            displayName = NormalizeProfileValue(request.PublicDisplayName, 200, required: true)!;
            organization = NormalizeProfileValue(request.OrganizationName, 200);
            country = NormalizeProfileValue(request.CountryOrRegion, 100);
            securityContact = new System.Net.Mail.MailAddress(request.SecurityContact.Trim()).Address.ToLowerInvariant();
            if (securityContact.Length > 320)
            {
                throw new ArgumentException("Security contact is invalid.");
            }
            publicContact = NormalizeProfileValue(request.PublicWebsiteContact, 320);
            if (publicContact is not null && (!Uri.TryCreate(publicContact, UriKind.Absolute, out var contactUri) ||
                contactUri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(contactUri.UserInfo)))
            {
                throw new ArgumentException("Public website contact must be an HTTPS URL.");
            }
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return new DomainCertificateIdentityProfileResult(DomainCertificateIdentityProfileStatus.InvalidRequest);
        }

        try
        {
            var enrollment = await enrollmentRepository.GetCurrentAsync(ownerId, normalized, cancellationToken).ConfigureAwait(false);
            if (enrollment is null)
            {
                return new DomainCertificateIdentityProfileResult(DomainCertificateIdentityProfileStatus.NotFound);
            }
            if (enrollment.Status != DomainEnrollmentStatus.PendingSecurityReview ||
                enrollment.DnsVerifiedAtUtc is null || enrollment.WebsiteVerifiedAtUtc is null)
            {
                return new DomainCertificateIdentityProfileResult(DomainCertificateIdentityProfileStatus.NotReady);
            }

            var securityHash = $"sha256:{Digest(securityContact)}";
            var publicOrganization = request.PublishOrganization ? organization : null;
            var publicCountry = request.PublishCountryOrRegion ? country : null;
            var identity = Digest($"{ownerId}\n{normalized}");
            var profileDigest = Digest($"{displayName}\n{publicOrganization}\n{publicContact}\n{publicCountry}\n{securityHash}");
            var write = await enrollmentRepository.TryCompleteIdentityProfileAsync(
                new DomainCertificateIdentityProfileRecord(
                    enrollment.EnrollmentId, ownerId, normalized, displayName, publicOrganization,
                    publicContact, publicCountry, securityHash, timeProvider.GetUtcNow(),
                    $"certificate-event:{Digest($"identity-profile\n{identity}\n{profileDigest}")}"),
                cancellationToken).ConfigureAwait(false);
            return new DomainCertificateIdentityProfileResult(write.Status switch
            {
                DomainEnrollmentTransitionWriteStatus.Updated => DomainCertificateIdentityProfileStatus.Completed,
                DomainEnrollmentTransitionWriteStatus.AlreadyApplied => DomainCertificateIdentityProfileStatus.Existing,
                DomainEnrollmentTransitionWriteStatus.NotFound => DomainCertificateIdentityProfileStatus.NotFound,
                _ => DomainCertificateIdentityProfileStatus.Conflict
            });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return new DomainCertificateIdentityProfileResult(DomainCertificateIdentityProfileStatus.Unavailable);
        }
    }

    private static string? NormalizeProfileValue(string? value, int maximumLength, bool required = false)
    {
        var normalized = value?.Trim();
        if ((required && string.IsNullOrWhiteSpace(normalized)) || normalized?.Length > maximumLength ||
            normalized?.Any(character => char.IsControl(character) || char.IsSurrogate(character)) == true)
        {
            throw new ArgumentException("Certificate identity profile text is invalid.");
        }
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static string Digest(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void ValidateIdentifier(string value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("Owner identifier is invalid.");
        }
    }

    private static DomainCertificateEnrollmentStartResult Result(DomainCertificateEnrollmentStartStatus status) =>
        new(status);
}
