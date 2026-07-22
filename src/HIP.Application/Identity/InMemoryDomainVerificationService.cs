using System.Collections.Concurrent;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// In-memory verification helper used by focused tests and isolated local flows that do not need live DNS.
/// </summary>
public sealed class InMemoryDomainVerificationService(
    DomainVerificationLifecycleOptions? lifecycleOptions = null,
    TimeProvider? timeProvider = null) : IDomainVerificationService
{
    private readonly ConcurrentDictionary<string, DomainVerificationRequest> _requests = new(StringComparer.OrdinalIgnoreCase);
    private readonly DomainVerificationLifecycleOptions lifecycle =
        (lifecycleOptions ?? DomainVerificationLifecycleOptions.Default).Validate();
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Creates an in-memory verification challenge.
    /// </summary>
    /// <param name="domain">Domain controlled by the website owner.</param>
    /// <param name="method">Verification method requested by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The created verification request.</returns>
    public Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
    {
        if (method is not (VerificationMethod.DnsTxt or VerificationMethod.WellKnownHipJson))
        {
            throw new ArgumentException("MVP verification supports DNS TXT and .well-known/hip.json only.", nameof(method));
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var now = clock.GetUtcNow();
        var request = new DomainVerificationRequest(
            normalized,
            method,
            Guid.NewGuid().ToString("N"),
            VerificationStatus.Pending,
            now,
            null,
            now.Add(lifecycle.ChallengeLifetime));
        if (!_requests.TryAdd(Key(normalized, method), request))
        {
            throw new InvalidOperationException(
                $"A domain verification challenge already exists for '{normalized}' and cannot be replaced by starting a new challenge.");
        }

        return Task.FromResult(request);
    }

    /// <inheritdoc />
    public Task<DomainVerificationRequest> GetOrStartAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (method is not (VerificationMethod.DnsTxt or VerificationMethod.WellKnownHipJson))
        {
            throw new ArgumentException("MVP verification supports DNS TXT and .well-known/hip.json only.", nameof(method));
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = _requests.GetOrAdd(
            Key(normalized, method),
            _ =>
            {
                var now = clock.GetUtcNow();
                return new DomainVerificationRequest(
                normalized,
                method,
                Guid.NewGuid().ToString("N"),
                VerificationStatus.Pending,
                now,
                null,
                now.Add(lifecycle.ChallengeLifetime));
            });
        return Task.FromResult(request);
    }

    /// <inheritdoc />
    public Task<DomainVerificationRequest?> GetAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        _requests.TryGetValue(Key(normalized, method), out var request);
        return Task.FromResult(request);
    }

    /// <summary>
    /// Verifies an in-memory challenge by exact token match.
    /// </summary>
    /// <param name="domain">Domain being verified.</param>
    /// <param name="method">Verification method used for the challenge.</param>
    /// <param name="token">Expected verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The updated verification request.</returns>
    public Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var key = Key(normalized, method);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_requests.TryGetValue(key, out var request))
            {
                throw new ArgumentException("Domain verification request was not found.", nameof(domain));
            }
            if (request.Status == VerificationStatus.Revoked)
            {
                throw new InvalidOperationException("Revoked domain verification cannot be retried or reactivated.");
            }
            if (IsExpired(request))
            {
                var expired = Expired(request);
                if (_requests.TryUpdate(key, expired, request))
                {
                    return Task.FromResult(expired);
                }
                continue;
            }

            var status = string.Equals(request.Token, token, StringComparison.Ordinal)
                ? VerificationStatus.Verified
                : VerificationStatus.Unverified;
            var updated = request with
            {
                Status = status,
                VerifiedAtUtc = status == VerificationStatus.Verified ? clock.GetUtcNow() : null,
                LastCheckedAtUtc = clock.GetUtcNow(),
                LastCheckMessage = status == VerificationStatus.Verified
                    ? "Domain verification succeeded."
                    : "The verification evidence did not match the active challenge."
            };
            if (_requests.TryUpdate(key, updated, request))
            {
                return Task.FromResult(updated);
            }
        }
    }

    /// <summary>
    /// Retries a stored in-memory challenge without accepting token input.
    /// </summary>
    public async Task<DomainVerificationRetryResult> RetryAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        if (method != VerificationMethod.DnsTxt)
        {
            throw new InvalidOperationException("Automated retry is available only for production DNS TXT verification.");
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        if (!_requests.TryGetValue(Key(normalized, method), out var request))
        {
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        }
        if (request.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot be retried.");
        }
        if (IsExpired(request))
        {
            var expired = Expired(request);
            _requests.TryUpdate(Key(normalized, method), expired, request);
            return new DomainVerificationRetryResult(
                expired,
                new DomainVerificationCheckResult(
                    normalized,
                    $"_hip.{normalized}",
                    DomainVerificationCheckStatus.PendingVerification,
                    clock.GetUtcNow(),
                    "The verification challenge expired. Issue a new challenge before checking again."));
        }

        var updated = await VerifyAsync(normalized, method, request.Token, cancellationToken);
        var check = new DomainVerificationCheckResult(
            normalized,
            $"_hip.{normalized}",
            DomainVerificationCheckStatus.Verified,
            DateTimeOffset.UtcNow,
            "HIP found the expected DNS TXT record for this domain.");
        return new DomainVerificationRetryResult(updated, check);
    }

    /// <summary>
    /// Revokes a stored in-memory challenge.
    /// </summary>
    public Task<DomainVerificationRequest> RevokeAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var key = Key(normalized, method);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_requests.TryGetValue(key, out var request))
            {
                throw new ArgumentException("Domain verification request was not found.", nameof(domain));
            }
            if (request.Status == VerificationStatus.Revoked)
            {
                return Task.FromResult(request);
            }

            var now = clock.GetUtcNow();
            var revoked = request with
            {
                Status = VerificationStatus.Revoked,
                VerifiedAtUtc = null,
                LastCheckedAtUtc = now,
                LastCheckMessage = "Domain verification was revoked.",
                RevokedAtUtc = now
            };
            if (_requests.TryUpdate(key, revoked, request))
            {
                return Task.FromResult(revoked);
            }
        }
    }

    public Task<DomainVerificationRequest> RenewExpiredAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var key = Key(normalized, method);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_requests.TryGetValue(key, out var request))
            {
                throw new ArgumentException("Domain verification request was not found.", nameof(domain));
            }
            if (request.Status == VerificationStatus.Revoked)
            {
                throw new InvalidOperationException("Revoked domain verification cannot issue another challenge.");
            }
            if (request.Status != VerificationStatus.Expired && !IsExpired(request))
            {
                throw new InvalidOperationException("Only an expired verification challenge can be renewed.");
            }

            var now = clock.GetUtcNow();
            var renewed = request with
            {
                Token = Guid.NewGuid().ToString("N"),
                Status = VerificationStatus.Pending,
                CreatedAtUtc = now,
                VerifiedAtUtc = null,
                ExpiresAtUtc = now.Add(lifecycle.ChallengeLifetime),
                LastCheckedAtUtc = null,
                LastCheckMessage = "A new domain verification challenge was issued.",
                RevokedAtUtc = null,
                ChallengeVersion = checked(request.ChallengeVersion + 1)
            };
            if (_requests.TryUpdate(key, renewed, request))
            {
                return Task.FromResult(renewed);
            }
        }
    }

    /// <summary>
    /// Performs a deterministic in-memory DNS-style check for tests without doing network I/O.
    /// </summary>
    /// <param name="domain">Domain whose record would be checked.</param>
    /// <param name="expectedToken">Expected verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>A verified result only when an in-memory DNS challenge exists for the exact token.</returns>
    public Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        if (string.IsNullOrWhiteSpace(expectedToken))
        {
            throw new ArgumentException("Expected verification token is required.", nameof(expectedToken));
        }

        var status = _requests.TryGetValue(Key(normalized, VerificationMethod.DnsTxt), out var request)
            ? string.Equals(request.Token, expectedToken, StringComparison.Ordinal)
                ? DomainVerificationCheckStatus.Verified
                : DomainVerificationCheckStatus.Invalid
            : DomainVerificationCheckStatus.NotConfigured;

        return Task.FromResult(new DomainVerificationCheckResult(
            normalized,
            $"_hip.{normalized}",
            status,
            DateTimeOffset.UtcNow,
            status == DomainVerificationCheckStatus.Verified
                ? "HIP found the expected DNS TXT record for this domain."
                : "HIP did not verify this domain in the in-memory test store."));
    }

    /// <summary>
    /// Creates a stable lookup key for in-memory verification requests.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="method">Verification method.</param>
    /// <returns>Dictionary key.</returns>
    private static string Key(string domain, VerificationMethod method) => $"{method}:{domain}";

    private bool IsExpired(DomainVerificationRequest request) =>
        request.Status == VerificationStatus.Expired ||
        (request.Status != VerificationStatus.Verified &&
         (request.ExpiresAtUtc ?? request.CreatedAtUtc.Add(lifecycle.ChallengeLifetime)) <= clock.GetUtcNow());

    private DomainVerificationRequest Expired(DomainVerificationRequest request) => request with
    {
        Status = VerificationStatus.Expired,
        VerifiedAtUtc = null,
        ExpiresAtUtc = request.ExpiresAtUtc ?? request.CreatedAtUtc.Add(lifecycle.ChallengeLifetime),
        LastCheckedAtUtc = clock.GetUtcNow(),
        LastCheckMessage = "The domain verification challenge expired before it was completed."
    };
}
