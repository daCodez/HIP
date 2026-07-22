using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Identity;
using HIP.Domain.Review;

namespace HIP.Application.Identity;

/// <summary>
/// Registers and verifies website identities with durable persistence so HIP can prove origin across restarts.
/// </summary>
public sealed class WebsiteIdentityService(
    IHipCryptoProvider cryptoProvider,
    IHipIdentityRepository hipIdentityRepository,
    IDomainVerificationService domainVerificationService,
    IWebsiteIdentityRepository websiteIdentityRepository,
    IAuditLogService auditLogService,
    ISigningKeyLifecycleService signingKeyLifecycleService,
    ISigningKeyLifecycleRepository signingKeyLifecycleRepository,
    IWebsiteOwnershipClaimRepository? ownershipClaimRepository = null,
    IPrivacyHashingService? privacyHashingService = null) : IWebsiteIdentityService
{
    private const string InitialKeyId = HipIdentityService.InitialSigningKeyId;
    private const string NewRegistrationWarning =
        "Development private key is returned once by the non-production placeholder crypto provider and cannot be reissued by HIP.";
    private const string RecoveryWarning =
        "Registration recovered using the existing public key. HIP did not retain or reissue the development private key; rotate to client-owned key material before signing.";
    private readonly IWebsiteOwnershipClaimRepository ownershipClaims =
        ownershipClaimRepository ?? new InMemoryWebsiteOwnershipClaimRepository();
    private readonly IPrivacyHashingService privacyHasher =
        privacyHashingService ?? new Sha256PrivacyHashingService();

    /// <summary>
    /// Registers a website identity and creates a DNS or well-known verification challenge.
    /// </summary>
    /// <param name="request">Website registration request from an owner or admin.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Registration details, including the verification challenge and development private key warning.</returns>
    public Task<WebsiteIdentityRegistrationResponse> RegisterAsync(
        WebsiteIdentityRegistrationRequest request,
        CancellationToken cancellationToken) =>
        RegisterAsync(request, "system:legacy-website-registration", "Owner", cancellationToken);

    public async Task<WebsiteIdentityRegistrationResponse> RegisterAsync(
        WebsiteIdentityRegistrationRequest request,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.VerificationMethod is not (VerificationMethod.DnsTxt or VerificationMethod.WellKnownHipJson))
        {
            throw new ArgumentException("Signed website MVP supports DNS TXT and .well-known/hip.json verification first.", nameof(request));
        }

        var domain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        await RequireDomainAccessAsync(domain, actorId, actorRole, createClaim: true, cancellationToken)
            .ConfigureAwait(false);
        var identityId = $"hip:web:{domain}";
        var existingWebsite = await websiteIdentityRepository.GetAsync(domain, cancellationToken)
            .ConfigureAwait(false);
        var storedIdentity = await signingKeyLifecycleRepository.GetRegisteredIdentityAsync(
                identityId,
                cancellationToken)
            .ConfigureAwait(false);
        var storedRing = await signingKeyLifecycleRepository.GetAsync(identityId, cancellationToken)
            .ConfigureAwait(false);
        IdentitySigningKeyRegistrationResult registration;
        string? developmentPrivateKey;
        var isRecovery = storedIdentity is not null || storedRing is not null;
        if (!isRecovery)
        {
            if (existingWebsite is not null)
            {
                throw new WebsiteIdentityRegistrationConflictException(domain);
            }

            var keyPair = cryptoProvider.GenerateKeyPair();
            var identity = new HipIdentity(
                identityId,
                IdentitySubjectType.Website,
                string.IsNullOrWhiteSpace(request.DisplayName) ? domain : request.DisplayName.Trim(),
                keyPair.PublicKey,
                keyPair.Algorithm,
                VerificationStatus.Pending,
                DateTimeOffset.UtcNow,
                domain);

            try
            {
                registration = await signingKeyLifecycleService.RegisterIdentityAsync(
                        new RegisterIdentitySigningKeyRequest(
                            identity,
                            InitialKeyId,
                            "system:website-registration",
                            "Register the website identity and its initial managed signing key.",
                            identity.CreatedAtUtc),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is IdentitySigningKeyRegistrationConflictException or
                    IdentitySigningKeyRegistrationInconsistencyException)
            {
                throw new WebsiteIdentityRegistrationConflictException(domain, exception);
            }

            var registeredKey = RequiredCanonicalInitialKey(registration, identityId, domain);
            if (!string.Equals(
                    registeredKey.PublicKey,
                    keyPair.PublicKey,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    registeredKey.Algorithm,
                    keyPair.Algorithm,
                    StringComparison.Ordinal))
            {
                throw new WebsiteIdentityRegistrationConflictException(domain);
            }

            developmentPrivateKey = keyPair.PrivateKey;
        }
        else
        {
            if (storedIdentity is null || storedRing is null)
            {
                throw new WebsiteIdentityRegistrationConflictException(domain);
            }

            registration = new IdentitySigningKeyRegistrationResult(storedIdentity, storedRing);
            developmentPrivateKey = null;
        }

        var canonicalKey = RequiredCanonicalInitialKey(registration, identityId, domain);
        if (existingWebsite is not null)
        {
            _ = RequiredCanonicalInitialKey(
                registration,
                identityId,
                domain,
                existingWebsite);
            EnsureVerificationMethod(existingWebsite, request.VerificationMethod, domain);
            var completedChallenge = await domainVerificationService.GetAsync(
                    domain,
                    existingWebsite.PreferredVerificationMethod,
                    cancellationToken)
                .ConfigureAwait(false);
            if (completedChallenge is not null)
            {
                EnsureVerificationBinding(
                    completedChallenge,
                    domain,
                    existingWebsite.PreferredVerificationMethod);
                if (existingWebsite.VerificationStatus is not (
                        VerificationStatus.Pending or VerificationStatus.Unverified) ||
                    completedChallenge.Status is not (
                        VerificationStatus.Pending or VerificationStatus.Unverified))
                {
                    throw new WebsiteIdentityRegistrationConflictException(domain);
                }
            }
        }

        var candidateWebsite = new WebsiteIdentity(
            domain,
            registration.Identity.IdentityId,
            [new SigningKey(canonicalKey.KeyId, canonicalKey.Algorithm, canonicalKey.PublicKey)],
            VerificationStatus.Pending,
            request.VerificationMethod,
            registration.Identity.CreatedAtUtc,
            null);
        var website = existingWebsite ?? await GetOrCreateWebsiteAsync(candidateWebsite, cancellationToken)
            .ConfigureAwait(false);
        _ = RequiredCanonicalInitialKey(registration, identityId, domain, website);
        EnsureVerificationMethod(website, request.VerificationMethod, domain);

        var verification = await domainVerificationService.GetOrStartAsync(
                domain,
                website.PreferredVerificationMethod,
                cancellationToken)
            .ConfigureAwait(false);
        EnsureVerificationBinding(
            verification,
            domain,
            website.PreferredVerificationMethod);

        // Registration recovery never owns verification-state transitions. Re-read the durable
        // website so a concurrent verification or revocation cannot be overwritten by stale state.
        website = await websiteIdentityRepository.GetAsync(domain, cancellationToken)
                .ConfigureAwait(false) ??
            throw new WebsiteIdentityRegistrationConflictException(domain);
        _ = RequiredCanonicalInitialKey(registration, identityId, domain, website);
        EnsureVerificationMethod(website, request.VerificationMethod, domain);

        return new WebsiteIdentityRegistrationResponse(
            website,
            verification,
            developmentPrivateKey,
            isRecovery ? RecoveryWarning : NewRegistrationWarning,
            IsRecovery: isRecovery,
            RequiresSigningKeyRotation: isRecovery);
    }

    /// <summary>
    /// Verifies a registered website identity using its stored challenge and updates durable identity status.
    /// </summary>
    /// <param name="request">Verification request containing the domain, method, and owner-supplied token.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The updated website identity.</returns>
    public Task<WebsiteIdentity> VerifyAsync(
        WebsiteVerificationRequest request,
        CancellationToken cancellationToken) =>
        VerifyAsync(request, "system:legacy-website-registration", "Owner", cancellationToken);

    public async Task<WebsiteIdentity> VerifyAsync(
        WebsiteVerificationRequest request,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        var domain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        await RequireDomainAccessAsync(domain, actorId, actorRole, createClaim: false, cancellationToken)
            .ConfigureAwait(false);
        var website = await websiteIdentityRepository.GetAsync(domain, cancellationToken);
        if (website is null)
        {
            throw new ArgumentException("Website identity was not found.", nameof(request));
        }
        if (website.VerificationStatus == VerificationStatus.Revoked ||
            await IsCanonicalIdentityRevokedAsync(website.HipIdentityId, cancellationToken).ConfigureAwait(false))
        {
            await ReconcileTerminalRevocationAsync(website, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("Revoked website verification cannot be reactivated.");
        }

        EnsureVerificationMethod(website, request.Method, domain);
        var verification = await domainVerificationService.VerifyAsync(domain, request.Method, request.Token, cancellationToken);
        EnsureVerificationBinding(verification, domain, website.PreferredVerificationMethod);
        var updated = website with
        {
            VerificationStatus = verification.Status,
            VerifiedAtUtc = verification.VerifiedAtUtc,
            LastCheckedAtUtc = DateTimeOffset.UtcNow,
            LastCheckMessage = StatusMessage(verification.Status)
        };
        var identity = await SetIdentityVerificationStatusAsync(
                website.HipIdentityId,
                updated.VerificationStatus,
                cancellationToken)
            .ConfigureAwait(false);
        if (identity.VerificationStatus == VerificationStatus.Revoked)
        {
            await ReconcileTerminalRevocationAsync(website, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("Revoked website verification cannot be reactivated.");
        }

        return await TryApplyWebsiteTransitionAsync(website, updated, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a registered website identity by domain.
    /// </summary>
    /// <param name="domain">Domain to look up.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The registered website identity, or null when it is not registered.</returns>
    public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        return websiteIdentityRepository.GetAsync(normalized, cancellationToken);
    }

    public async Task<WebsiteIdentity?> GetAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        await RequireDomainAccessAsync(normalized, actorId, actorRole, createClaim: false, cancellationToken)
            .ConfigureAwait(false);
        return await websiteIdentityRepository.GetAsync(normalized, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Lists registered website identities newest first for domain-verification operations.
    /// </summary>
    public async Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
        (await websiteIdentityRepository.ListAsync(cancellationToken))
            .OrderByDescending(identity => identity.CreatedAtUtc)
            .ThenBy(identity => identity.Domain, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public async Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        var identities = await ListAsync(cancellationToken).ConfigureAwait(false);
        if (IsPrivilegedOwner(actorRole))
        {
            return identities;
        }

        var ownerHash = OwnerHash(actorId);
        var visible = new List<WebsiteIdentity>(identities.Count);
        foreach (var identity in identities)
        {
            var claim = await ownershipClaims.GetAsync(identity.Domain, cancellationToken).ConfigureAwait(false);
            if (claim is not null && string.Equals(claim.OwnerScopeHash, ownerHash, StringComparison.Ordinal))
            {
                visible.Add(identity);
            }
        }

        return visible;
    }

    /// <summary>
    /// Retries verification using the stored challenge without exposing its token to the admin.
    /// </summary>
    public async Task<WebsiteIdentity> RetryVerificationAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        await RequireDomainAccessAsync(domain, actorId, actorRole, createClaim: false, cancellationToken)
            .ConfigureAwait(false);
        var website = await RequiredWebsiteAsync(domain, cancellationToken);
        if (website.VerificationStatus == VerificationStatus.Revoked ||
            await IsCanonicalIdentityRevokedAsync(website.HipIdentityId, cancellationToken).ConfigureAwait(false))
        {
            await ReconcileTerminalRevocationAsync(website, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("Revoked domain verification cannot be retried.");
        }

        var result = await domainVerificationService.RetryAsync(
            website.Domain,
            website.PreferredVerificationMethod,
            cancellationToken);
        var updated = website with
        {
            VerificationStatus = result.Request.Status,
            VerifiedAtUtc = result.Request.VerifiedAtUtc,
            LastCheckedAtUtc = result.Check.CheckedAtUtc,
            LastCheckMessage = result.Check.Message
        };
        var identity = await SetIdentityVerificationStatusAsync(
                website.HipIdentityId,
                updated.VerificationStatus,
                cancellationToken)
            .ConfigureAwait(false);
        if (identity.VerificationStatus == VerificationStatus.Revoked)
        {
            await ReconcileTerminalRevocationAsync(website, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("Revoked domain verification cannot be retried.");
        }

        var persisted = await TryApplyWebsiteTransitionAsync(website, updated, cancellationToken)
            .ConfigureAwait(false);
        auditLogService.Write(
            actorId,
            "domain-verification.retried",
            TargetType.Domain,
            website.Domain,
            $"Domain verification retry completed with status {persisted.VerificationStatus}.",
            AuditSeverity.Medium,
            new Dictionary<string, string> { ["method"] = website.PreferredVerificationMethod.ToString() },
            actorRole,
            new Dictionary<string, string> { ["status"] = website.VerificationStatus.ToString() },
            new Dictionary<string, string> { ["status"] = persisted.VerificationStatus.ToString() });
        return persisted;
    }

    /// <summary>
    /// Revokes domain verification, synchronizes identity state, and writes a Critical audit entry.
    /// </summary>
    public async Task<WebsiteIdentity> RevokeVerificationAsync(
        string domain,
        string reason,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        var safeReason = ValidateRevocationReason(reason);
        await RequireDomainAccessAsync(domain, actorId, actorRole, createClaim: false, cancellationToken)
            .ConfigureAwait(false);
        var website = await RequiredWebsiteAsync(domain, cancellationToken);
        await SetIdentityVerificationStatusAsync(
                website.HipIdentityId,
                VerificationStatus.Revoked,
                cancellationToken)
            .ConfigureAwait(false);
        await domainVerificationService.RevokeAsync(
            website.Domain,
            website.PreferredVerificationMethod,
            cancellationToken);
        var now = website.RevokedAtUtc ?? DateTimeOffset.UtcNow;
        var revoked = website with
        {
            VerificationStatus = VerificationStatus.Revoked,
            VerifiedAtUtc = null,
            LastCheckedAtUtc = now,
            LastCheckMessage = "Domain verification was revoked by an authorized HIP owner.",
            RevokedAtUtc = now
        };
        var persisted = await RevokeWebsiteAsync(website, revoked, cancellationToken)
            .ConfigureAwait(false);

        auditLogService.WriteOnce(
            $"domain-verification.revoked:{website.Domain}",
            actorId,
            "domain-verification.revoked",
            TargetType.Domain,
            website.Domain,
            "Domain verification was revoked.",
            AuditSeverity.Critical,
            new Dictionary<string, string> { ["reason"] = safeReason },
            actorRole,
            new Dictionary<string, string> { ["status"] = website.VerificationStatus.ToString() },
            new Dictionary<string, string> { ["status"] = VerificationStatus.Revoked.ToString() });
        return persisted;
    }

    public async Task<WebsiteIdentityRegistrationResponse> RenewExpiredVerificationAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        await RequireDomainAccessAsync(domain, actorId, actorRole, createClaim: false, cancellationToken)
            .ConfigureAwait(false);
        var website = await RequiredWebsiteAsync(domain, cancellationToken).ConfigureAwait(false);
        if (website.VerificationStatus == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot issue another challenge.");
        }

        var challenge = await domainVerificationService.RenewExpiredAsync(
            website.Domain,
            website.PreferredVerificationMethod,
            cancellationToken).ConfigureAwait(false);
        var updated = website with
        {
            VerificationStatus = VerificationStatus.Pending,
            VerifiedAtUtc = null,
            LastCheckedAtUtc = challenge.CreatedAtUtc,
            LastCheckMessage = "A new domain verification challenge was issued."
        };
        var persisted = await TryApplyWebsiteTransitionAsync(website, updated, cancellationToken)
            .ConfigureAwait(false);
        auditLogService.Write(
            actorId,
            "domain-verification.renewed",
            TargetType.Domain,
            website.Domain,
            "An expired domain verification challenge was renewed.",
            AuditSeverity.Medium,
            new Dictionary<string, string> { ["challengeVersion"] = challenge.ChallengeVersion.ToString() },
            actorRole);
        return new WebsiteIdentityRegistrationResponse(
            persisted,
            challenge,
            null,
            "Expired challenge renewed. HIP did not issue or expose signing private key material.",
            IsRecovery: true,
            RequiresSigningKeyRotation: false);
    }

    private async Task RequireDomainAccessAsync(
        string domain,
        string actorId,
        string actorRole,
        bool createClaim,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var ownerHash = OwnerHash(actorId);
        var role = RequiredActorValue(actorRole, nameof(actorRole));
        var claim = await ownershipClaims.GetAsync(normalized, cancellationToken).ConfigureAwait(false);
        if (claim is null && createClaim)
        {
            var candidate = new WebsiteOwnershipClaim(normalized, ownerHash, role, DateTimeOffset.UtcNow);
            if (await ownershipClaims.TryCreateAsync(candidate, cancellationToken).ConfigureAwait(false))
            {
                claim = candidate;
            }
            else
            {
                claim = await ownershipClaims.GetAsync(normalized, cancellationToken).ConfigureAwait(false);
            }
        }

        if (claim is null && IsPrivilegedOwner(role))
        {
            return;
        }

        if (claim is null ||
            (!string.Equals(claim.OwnerScopeHash, ownerHash, StringComparison.Ordinal) && !IsPrivilegedOwner(role)))
        {
            throw new WebsiteIdentityRegistrationConflictException(normalized);
        }
    }

    private string OwnerHash(string actorId) =>
        privacyHasher.Hash($"website-owner:{RequiredActorValue(actorId, nameof(actorId))}");

    private static string RequiredActorValue(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > 160 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("Website owner identity metadata is invalid.", parameterName);
        }

        return normalized;
    }

    private static bool IsPrivilegedOwner(string actorRole) =>
        string.Equals(actorRole, "Owner", StringComparison.OrdinalIgnoreCase);

    private async Task<bool> IsCanonicalIdentityRevokedAsync(
        string identityId,
        CancellationToken cancellationToken)
    {
        var identity = await hipIdentityRepository.GetAsync(identityId, cancellationToken)
            .ConfigureAwait(false) ??
            throw new InvalidOperationException($"Canonical HIP identity '{identityId}' was not found.");
        return identity.VerificationStatus == VerificationStatus.Revoked;
    }

    private async Task<WebsiteIdentity> ReconcileTerminalRevocationAsync(
        WebsiteIdentity website,
        CancellationToken cancellationToken)
    {
        await SetIdentityVerificationStatusAsync(
                website.HipIdentityId,
                VerificationStatus.Revoked,
                cancellationToken)
            .ConfigureAwait(false);
        await domainVerificationService.RevokeAsync(
                website.Domain,
                website.PreferredVerificationMethod,
                cancellationToken)
            .ConfigureAwait(false);

        var now = website.RevokedAtUtc ?? DateTimeOffset.UtcNow;
        return await RevokeWebsiteAsync(
                website,
                website with
                {
                    VerificationStatus = VerificationStatus.Revoked,
                    VerifiedAtUtc = null,
                    LastCheckedAtUtc = now,
                    LastCheckMessage = website.LastCheckMessage ?? "The canonical HIP identity is revoked.",
                    RevokedAtUtc = now
                },
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<HipIdentity> SetIdentityVerificationStatusAsync(
        string identityId,
        VerificationStatus status,
        CancellationToken cancellationToken)
    {
        var current = await hipIdentityRepository.GetAsync(identityId, cancellationToken)
            .ConfigureAwait(false) ??
            throw new InvalidOperationException($"Canonical HIP identity '{identityId}' was not found.");
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (current.VerificationStatus == VerificationStatus.Revoked ||
                current.VerificationStatus == status)
            {
                return current;
            }

            var updated = current with { VerificationStatus = status };
            if (await hipIdentityRepository.TryUpdateAsync(current, updated, cancellationToken)
                    .ConfigureAwait(false))
            {
                return updated;
            }

            current = await hipIdentityRepository.GetAsync(identityId, cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException($"Canonical HIP identity '{identityId}' was not found.");
        }

        throw new InvalidOperationException("HIP identity verification state changed concurrently; retry the operation.");
    }

    private async Task<WebsiteIdentity> RequiredWebsiteAsync(string domain, CancellationToken cancellationToken) =>
        await GetAsync(domain, cancellationToken) ??
            throw new ArgumentException("Website identity was not found.", nameof(domain));

    private async Task<WebsiteIdentity> TryApplyWebsiteTransitionAsync(
        WebsiteIdentity expected,
        WebsiteIdentity updated,
        CancellationToken cancellationToken)
    {
        if (await websiteIdentityRepository.TryUpdateAsync(expected, updated, cancellationToken)
                .ConfigureAwait(false))
        {
            return updated;
        }

        var current = await RequiredWebsiteAsync(expected.Domain, cancellationToken)
            .ConfigureAwait(false);
        if (current.VerificationStatus == VerificationStatus.Revoked)
        {
            return current;
        }

        throw new InvalidOperationException("Website verification state changed concurrently; retry the operation.");
    }

    private async Task<WebsiteIdentity> RevokeWebsiteAsync(
        WebsiteIdentity initial,
        WebsiteIdentity firstRevokedSnapshot,
        CancellationToken cancellationToken)
    {
        var current = initial;
        var revokedAtUtc = firstRevokedSnapshot.RevokedAtUtc ?? DateTimeOffset.UtcNow;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (current.VerificationStatus == VerificationStatus.Revoked &&
                current.RevokedAtUtc is not null &&
                current.LastCheckedAtUtc is not null &&
                !string.IsNullOrWhiteSpace(current.LastCheckMessage))
            {
                return current;
            }

            var revoked = current with
            {
                VerificationStatus = VerificationStatus.Revoked,
                VerifiedAtUtc = null,
                LastCheckedAtUtc = revokedAtUtc,
                LastCheckMessage = firstRevokedSnapshot.LastCheckMessage,
                RevokedAtUtc = revokedAtUtc
            };
            if (await websiteIdentityRepository.TryUpdateAsync(current, revoked, cancellationToken)
                    .ConfigureAwait(false))
            {
                return revoked;
            }

            current = await RequiredWebsiteAsync(current.Domain, cancellationToken)
                .ConfigureAwait(false);
        }

        throw new InvalidOperationException("Website revocation could not win concurrent updates.");
    }

    /// <summary>
    /// Atomically elects the website registration or reconciles a create that committed before failing.
    /// </summary>
    private async Task<WebsiteIdentity> GetOrCreateWebsiteAsync(
        WebsiteIdentity candidate,
        CancellationToken cancellationToken)
    {
        try
        {
            if (await websiteIdentityRepository.TryCreateAsync(candidate, cancellationToken)
                    .ConfigureAwait(false))
            {
                return candidate;
            }
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            var committed = await websiteIdentityRepository.GetAsync(candidate.Domain, cancellationToken)
                .ConfigureAwait(false);
            if (committed is not null)
            {
                return committed;
            }

            throw;
        }

        return await websiteIdentityRepository.GetAsync(candidate.Domain, cancellationToken)
                .ConfigureAwait(false) ??
            throw new InvalidOperationException(
                $"Website registration for '{candidate.Domain}' could not be created or reconciled.");
    }

    /// <summary>
    /// Prevents a retry from changing the verification method elected by the durable website record.
    /// </summary>
    private static void EnsureVerificationMethod(
        WebsiteIdentity website,
        VerificationMethod requestedMethod,
        string domain)
    {
        if (website.PreferredVerificationMethod != requestedMethod)
        {
            throw new WebsiteIdentityRegistrationConflictException(domain);
        }
    }

    /// <summary>
    /// Rejects a corrupted or incorrectly keyed challenge instead of returning unrelated verification state.
    /// </summary>
    private static void EnsureVerificationBinding(
        DomainVerificationRequest verification,
        string domain,
        VerificationMethod method)
    {
        if (!string.Equals(verification.Domain, domain, StringComparison.Ordinal) ||
            verification.Method != method)
        {
            throw new WebsiteIdentityRegistrationConflictException(domain);
        }
    }

    private static string ValidateRevocationReason(string reason)
    {
        var safeReason = reason?.Trim() ?? string.Empty;
        if (safeReason.Length is < 5 or > 500)
        {
            throw new ArgumentException("Revocation reason must be between 5 and 500 characters.", nameof(reason));
        }

        return safeReason;
    }

    private static string StatusMessage(VerificationStatus status) => status switch
    {
        VerificationStatus.Verified => "HIP confirmed domain control.",
        VerificationStatus.Unverified => "HIP found verification evidence that did not match.",
        VerificationStatus.Revoked => "Domain verification has been revoked.",
        VerificationStatus.Expired => "The domain verification challenge expired.",
        _ => "HIP has not confirmed domain control yet."
    };

    /// <summary>
    /// Builds the future .well-known/hip.json document for a registered website.
    /// </summary>
    /// <param name="domain">Domain whose well-known document should be generated.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Public identity document for the website.</returns>
    public Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(
        string domain,
        CancellationToken cancellationToken) =>
        BuildWellKnownDocumentAsync(
            domain,
            "system:legacy-well-known-document",
            "Owner",
            cancellationToken);

    public async Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        await RequireDomainAccessAsync(normalized, actorId, actorRole, createClaim: false, cancellationToken)
            .ConfigureAwait(false);
        var website = await websiteIdentityRepository.GetAsync(normalized, cancellationToken)
            .ConfigureAwait(false) ??
            throw new ArgumentException("Website identity was not found.", nameof(domain));
        var challenge = await domainVerificationService.GetAsync(
                website.Domain,
                VerificationMethod.WellKnownHipJson,
                cancellationToken)
            .ConfigureAwait(false) ??
            throw new InvalidOperationException("An active well-known verification challenge was not found.");
        if (challenge.Status == VerificationStatus.Revoked ||
            challenge.ExpiresAtUtc is null ||
            challenge.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            throw new InvalidOperationException("The well-known verification challenge is not active.");
        }

        return new HipWellKnownDocument(
            website.Domain,
            website.HipIdentityId,
            website.PublicKeys,
            DateTimeOffset.UtcNow,
            SchemaVersion: "1",
            VerificationChallenge: challenge.Token,
            ExpiresAtUtc: challenge.ExpiresAtUtc);
    }

    /// <summary>
    /// Verifies that canonical identity, lifecycle, and optional website snapshots all name the same key.
    /// </summary>
    private ManagedSigningKey RequiredCanonicalInitialKey(
        IdentitySigningKeyRegistrationResult registration,
        string identityId,
        string domain,
        WebsiteIdentity? website = null)
    {
        try
        {
            var identity = registration.Identity;
            var keyRing = registration.KeyRing;
            var key = keyRing.Keys.SingleOrDefault(candidate =>
                string.Equals(candidate.KeyId, InitialKeyId, StringComparison.Ordinal));
            if (key is null ||
                !string.Equals(identity.IdentityId, identityId, StringComparison.Ordinal) ||
                identity.IdentityType != IdentitySubjectType.Website ||
                identity.VerificationStatus == VerificationStatus.Revoked ||
                !string.Equals(identity.ReputationTargetId, domain, StringComparison.Ordinal) ||
                !string.Equals(keyRing.IdentityId, identityId, StringComparison.Ordinal) ||
                !string.Equals(identity.KeyAlgorithm, key.Algorithm, StringComparison.Ordinal) ||
                !string.Equals(identity.PublicKey, key.PublicKey, StringComparison.Ordinal))
            {
                throw new WebsiteIdentityRegistrationConflictException(domain);
            }

            if (website is not null)
            {
                var websiteKey = website.PublicKeys.SingleOrDefault(candidate =>
                    string.Equals(candidate.KeyId, InitialKeyId, StringComparison.Ordinal));
                if (!string.Equals(website.Domain, domain, StringComparison.Ordinal) ||
                    !string.Equals(website.HipIdentityId, identityId, StringComparison.Ordinal) ||
                    website.PublicKeys.Count != 1 ||
                    websiteKey is null ||
                    !string.Equals(websiteKey.Algorithm, key.Algorithm, StringComparison.Ordinal) ||
                    !string.Equals(websiteKey.PublicKey, key.PublicKey, StringComparison.Ordinal))
                {
                    throw new WebsiteIdentityRegistrationConflictException(domain);
                }
            }

            return key;
        }
        catch (WebsiteIdentityRegistrationConflictException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or NotSupportedException)
        {
            throw new WebsiteIdentityRegistrationConflictException(domain, exception);
        }
    }
}

/// <summary>
/// Indicates that deterministic website registration is already claimed or internally inconsistent.
/// </summary>
public sealed class WebsiteIdentityRegistrationConflictException : InvalidOperationException
{
    /// <summary>Creates a privacy-safe conflict that never discloses key material or fingerprints.</summary>
    public WebsiteIdentityRegistrationConflictException(string domain, Exception? innerException = null)
        : base(
            $"Website identity registration for '{domain}' conflicts with an existing claim. " +
            "Existing key material was preserved; the private key is not reissued.",
            innerException)
    {
        Domain = domain;
    }

    /// <summary>Gets the normalized public domain associated with the conflict.</summary>
    public string Domain { get; }
}
