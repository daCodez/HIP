using System.Collections.Concurrent;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public sealed class InMemoryDomainVerificationService : IDomainVerificationService
{
    private readonly ConcurrentDictionary<string, DomainVerificationRequest> _requests = new(StringComparer.OrdinalIgnoreCase);

    public Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
    {
        if (method is not (VerificationMethod.DnsTxt or VerificationMethod.WellKnownHipJson))
        {
            throw new ArgumentException("MVP verification supports DNS TXT and .well-known/hip.json only.", nameof(method));
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = new DomainVerificationRequest(
            normalized,
            method,
            $"hip-domain-verification={Guid.NewGuid():N}",
            VerificationStatus.Pending,
            DateTimeOffset.UtcNow,
            null);
        _requests[Key(normalized, method)] = request;
        return Task.FromResult(request);
    }

    public Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        if (!_requests.TryGetValue(Key(normalized, method), out var request))
        {
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        }

        var status = string.Equals(request.Token, token, StringComparison.Ordinal)
            ? VerificationStatus.Verified
            : VerificationStatus.Unverified;
        var updated = request with
        {
            Status = status,
            VerifiedAtUtc = status == VerificationStatus.Verified ? DateTimeOffset.UtcNow : null
        };
        _requests[Key(normalized, method)] = updated;
        return Task.FromResult(updated);
    }

    private static string Key(string domain, VerificationMethod method) => $"{method}:{domain}";
}
