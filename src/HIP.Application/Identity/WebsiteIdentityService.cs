using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Registers and verifies website identities with durable persistence so HIP can prove origin across restarts.
/// </summary>
public sealed class WebsiteIdentityService(
    IHipCryptoProvider cryptoProvider,
    IHipIdentityRepository identityRepository,
    IDomainVerificationService domainVerificationService,
    IWebsiteIdentityRepository websiteIdentityRepository) : IWebsiteIdentityService
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
            VerifiedAtUtc = verification.VerifiedAtUtc
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
