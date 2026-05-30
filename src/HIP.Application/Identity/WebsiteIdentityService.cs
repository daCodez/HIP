using System.Collections.Concurrent;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public sealed class WebsiteIdentityService(
    IHipCryptoProvider cryptoProvider,
    IHipIdentityRepository identityRepository,
    IDomainVerificationService domainVerificationService) : IWebsiteIdentityService
{
    private static readonly ConcurrentDictionary<string, WebsiteIdentity> Websites = new(StringComparer.OrdinalIgnoreCase);

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

        Websites[domain] = website;

        return new WebsiteIdentityRegistrationResponse(
            website,
            verification,
            keyPair.PrivateKey,
            "Development private key is returned only by the non-production placeholder crypto provider.");
    }

    public async Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, CancellationToken cancellationToken)
    {
        var domain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        if (!Websites.TryGetValue(domain, out var website))
        {
            throw new ArgumentException("Website identity was not found.", nameof(request));
        }

        var verification = await domainVerificationService.VerifyAsync(domain, request.Method, request.Token, cancellationToken);
        var updated = website with
        {
            VerificationStatus = verification.Status,
            VerifiedAtUtc = verification.VerifiedAtUtc
        };
        Websites[domain] = updated;
        return updated;
    }

    public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        Websites.TryGetValue(normalized, out var website);
        return Task.FromResult(website);
    }

    public async Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(string domain, CancellationToken cancellationToken)
    {
        var website = await GetAsync(domain, cancellationToken) ??
            throw new ArgumentException("Website identity was not found.", nameof(domain));

        return new HipWellKnownDocument(website.Domain, website.HipIdentityId, website.PublicKeys, DateTimeOffset.UtcNow);
    }
}
