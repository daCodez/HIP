using HIP.Application.PublicLookup;
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
    IHipIdentityRepository identityRepository,
    IDomainVerificationService domainVerificationService,
    IWebsiteIdentityRepository websiteIdentityRepository,
    IAuditLogService auditLogService) : IWebsiteIdentityService
{
    /// <summary>
    /// Registers a website identity and creates a DNS or well-known verification challenge.
    /// </summary>
    /// <param name="request">Website registration request from an owner or admin.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Registration details, including the verification challenge and development private key warning.</returns>
    public async Task<WebsiteIdentityRegistrationResponse> RegisterAsync(WebsiteIdentityRegistrationRequest request, CancellationToken cancellationToken)
    {
        if (request.VerificationMethod is not (VerificationMethod.DnsTxt or VerificationMethod.WellKnownHipJson))
        {
            throw new ArgumentException("Signed website MVP supports DNS TXT and .well-known/hip.json verification first.", nameof(request));
        }

        var domain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        var keyPair = cryptoProvider.GenerateKeyPair();
        var identity = new HipIdentity(
            $"hip:web:{domain}",
            IdentitySubjectType.Website,
            string.IsNullOrWhiteSpace(request.DisplayName) ? domain : request.DisplayName.Trim(),
            keyPair.PublicKey,
            keyPair.Algorithm,
            VerificationStatus.Pending,
            DateTimeOffset.UtcNow,
            domain);

        await identityRepository.SaveAsync(identity, cancellationToken);
        var verification = await domainVerificationService.StartAsync(domain, request.VerificationMethod, cancellationToken);
        var website = new WebsiteIdentity(
            domain,
            identity.IdentityId,
            [new SigningKey("default", keyPair.Algorithm, keyPair.PublicKey)],
            VerificationStatus.Pending,
            request.VerificationMethod,
            identity.CreatedAtUtc,
            null);

        await websiteIdentityRepository.SaveAsync(website, cancellationToken);

        return new WebsiteIdentityRegistrationResponse(
            website,
            verification,
            keyPair.PrivateKey,
            "Development private key is returned only by the non-production placeholder crypto provider.");
    }

    /// <summary>
    /// Verifies a registered website identity using its stored challenge and updates durable identity status.
    /// </summary>
    /// <param name="request">Verification request containing the domain, method, and owner-supplied token.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The updated website identity.</returns>
    public async Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, CancellationToken cancellationToken)
    {
        var domain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        var website = await websiteIdentityRepository.GetAsync(domain, cancellationToken);
        if (website is null)
        {
            throw new ArgumentException("Website identity was not found.", nameof(request));
        }

        var verification = await domainVerificationService.VerifyAsync(domain, request.Method, request.Token, cancellationToken);
        var updated = website with
        {
            VerificationStatus = verification.Status,
            VerifiedAtUtc = verification.VerifiedAtUtc,
            LastCheckedAtUtc = DateTimeOffset.UtcNow,
            LastCheckMessage = StatusMessage(verification.Status)
        };
        await websiteIdentityRepository.SaveAsync(updated, cancellationToken);

        var identity = await identityRepository.GetAsync(website.HipIdentityId, cancellationToken);
        if (identity is not null)
        {
            await identityRepository.SaveAsync(identity with { VerificationStatus = updated.VerificationStatus }, cancellationToken);
        }

        return updated;
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

    /// <summary>
    /// Lists registered website identities newest first for domain-verification operations.
    /// </summary>
    public async Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
        (await websiteIdentityRepository.ListAsync(cancellationToken))
            .OrderByDescending(identity => identity.CreatedAtUtc)
            .ThenBy(identity => identity.Domain, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    /// <summary>
    /// Retries verification using the stored challenge without exposing its token to the admin.
    /// </summary>
    public async Task<WebsiteIdentity> RetryVerificationAsync(
        string domain,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken)
    {
        var website = await RequiredWebsiteAsync(domain, cancellationToken);
        if (website.VerificationStatus == VerificationStatus.Revoked)
        {
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
        await SaveWebsiteAndIdentityStatusAsync(updated, cancellationToken);
        auditLogService.Write(
            actorId,
            "domain-verification.retried",
            TargetType.Domain,
            website.Domain,
            $"Domain verification retry completed with status {updated.VerificationStatus}.",
            AuditSeverity.Medium,
            new Dictionary<string, string> { ["method"] = website.PreferredVerificationMethod.ToString() },
            actorRole,
            new Dictionary<string, string> { ["status"] = website.VerificationStatus.ToString() },
            new Dictionary<string, string> { ["status"] = updated.VerificationStatus.ToString() });
        return updated;
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
        var website = await RequiredWebsiteAsync(domain, cancellationToken);
        if (website.VerificationStatus == VerificationStatus.Revoked)
        {
            return website;
        }

        await domainVerificationService.RevokeAsync(
            website.Domain,
            website.PreferredVerificationMethod,
            cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var revoked = website with
        {
            VerificationStatus = VerificationStatus.Revoked,
            VerifiedAtUtc = null,
            LastCheckedAtUtc = now,
            LastCheckMessage = "Domain verification was revoked by an authorized HIP owner.",
            RevokedAtUtc = now
        };
        await SaveWebsiteAndIdentityStatusAsync(revoked, cancellationToken);
        auditLogService.Write(
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
        return revoked;
    }

    private async Task<WebsiteIdentity> RequiredWebsiteAsync(string domain, CancellationToken cancellationToken) =>
        await GetAsync(domain, cancellationToken) ??
            throw new ArgumentException("Website identity was not found.", nameof(domain));

    private async Task SaveWebsiteAndIdentityStatusAsync(
        WebsiteIdentity website,
        CancellationToken cancellationToken)
    {
        await websiteIdentityRepository.SaveAsync(website, cancellationToken);
        var identity = await identityRepository.GetAsync(website.HipIdentityId, cancellationToken);
        if (identity is not null)
        {
            await identityRepository.SaveAsync(
                identity with { VerificationStatus = website.VerificationStatus },
                cancellationToken);
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
        _ => "HIP has not confirmed domain control yet."
    };

    /// <summary>
    /// Builds the future .well-known/hip.json document for a registered website.
    /// </summary>
    /// <param name="domain">Domain whose well-known document should be generated.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Public identity document for the website.</returns>
    public async Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(string domain, CancellationToken cancellationToken)
    {
        var website = await GetAsync(domain, cancellationToken) ??
            throw new ArgumentException("Website identity was not found.", nameof(domain));

        return new HipWellKnownDocument(website.Domain, website.HipIdentityId, website.PublicKeys, DateTimeOffset.UtcNow);
    }
}
