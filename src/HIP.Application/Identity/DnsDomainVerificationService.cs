using HIP.Application.PublicLookup;
using HIP.Domain.Identity;
using Microsoft.Extensions.Logging;

namespace HIP.Application.Identity;

/// <summary>
/// Verifies HIP website identity using DNS TXT records at _hip.{domain}.
/// </summary>
public sealed class DnsDomainVerificationService(
    IDnsTxtRecordResolver txtRecordResolver,
    IDomainVerificationRequestRepository verificationRepository,
    ILogger<DnsDomainVerificationService> logger,
    DomainVerificationLifecycleOptions? lifecycleOptions = null,
    TimeProvider? timeProvider = null,
    IWellKnownHipDocumentVerifier? wellKnownVerifier = null,
    IHtmlDomainVerificationEvidenceProvider? htmlEvidenceProvider = null) : IDomainVerificationService
{
    private const string VerificationPrefix = "hip-site-verification=";
    private readonly DomainVerificationLifecycleOptions lifecycle =
        (lifecycleOptions ?? DomainVerificationLifecycleOptions.Default).Validate();
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly IHtmlDomainVerificationEvidenceProvider htmlVerifier =
        htmlEvidenceProvider ?? new UnavailableHtmlDomainVerificationEvidenceProvider();

    /// <summary>
    /// Creates a domain verification challenge token for DNS TXT or .well-known based verification.
    /// </summary>
    /// <param name="domain">Domain controlled by the website owner.</param>
    /// <param name="method">Verification method requested by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The created verification request.</returns>
    public async Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
    {
        if (!IsSupportedMethod(method))
        {
            throw new ArgumentException("Unsupported domain verification method.", nameof(method));
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var now = clock.GetUtcNow();
        var request = new DomainVerificationRequest(
            normalized,
            method,
            DomainVerificationChallengeToken.Generate(),
            VerificationStatus.Pending,
            now,
            null,
            now.Add(lifecycle.ChallengeLifetime));

        if (!await verificationRepository.TryCreateAsync(request, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                $"A domain verification challenge already exists for '{normalized}' and cannot be replaced by starting a new challenge.");
        }

        return request;
    }

    /// <inheritdoc />
    public async Task<DomainVerificationRequest> GetOrStartAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        if (!IsSupportedMethod(method))
        {
            throw new ArgumentException("Unsupported domain verification method.", nameof(method));
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var now = clock.GetUtcNow();
        var request = new DomainVerificationRequest(
            normalized,
            method,
            DomainVerificationChallengeToken.Generate(),
            VerificationStatus.Pending,
            now,
            null,
            now.Add(lifecycle.ChallengeLifetime));

        try
        {
            if (await verificationRepository.TryCreateAsync(request, cancellationToken).ConfigureAwait(false))
            {
                return request;
            }
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            var committed = await verificationRepository.GetAsync(normalized, method, cancellationToken)
                .ConfigureAwait(false);
            if (committed is not null)
            {
                return committed;
            }

            throw;
        }

        return await verificationRepository.GetAsync(normalized, method, cancellationToken)
                .ConfigureAwait(false) ??
            throw new InvalidOperationException(
                $"Domain verification challenge for '{normalized}' could not be created or reconciled.");
    }

    /// <inheritdoc />
    public Task<DomainVerificationRequest?> GetAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        return verificationRepository.GetAsync(normalized, method, cancellationToken);
    }

    /// <summary>
    /// Verifies an existing domain challenge against live DNS or a fetched signed well-known document.
    /// </summary>
    /// <param name="domain">Domain being verified.</param>
    /// <param name="method">Verification method used for the challenge.</param>
    /// <param name="token">Expected verification token supplied by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The updated verification request.</returns>
    public async Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken);
        if (request is null)
        {
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        }
        if (request.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot be retried or reactivated.");
        }
        if (IsExpired(request))
        {
            return await ExpireAsync(request, cancellationToken).ConfigureAwait(false);
        }
        if (request.ConsumedAtUtc is not null)
        {
            throw new InvalidOperationException("This domain verification challenge has already been used.");
        }
        if (request.Status == VerificationStatus.Suspended || request.VerificationAttemptCount >= lifecycle.MaximumVerificationAttempts)
        {
            throw new InvalidOperationException("The verification attempt limit was reached; regenerate the challenge before retrying.");
        }

        VerificationStatus status;
        string message;
        if (method == VerificationMethod.DnsTxt)
        {
            status = TokensMatch(request.Token, token)
                ? MapDnsCheckStatus((await CheckDnsTxtAsync(normalized, request.Token, cancellationToken)).Status)
                : VerificationStatus.Unverified;
            message = StatusMessage(status);
        }
        else if (method == VerificationMethod.WellKnownHipJson)
        {
            if (!TokensMatch(request.Token, token))
            {
                status = VerificationStatus.Unverified;
                message = "The supplied verification challenge does not match the active domain claim.";
            }
            else if (wellKnownVerifier is null)
            {
                status = VerificationStatus.Pending;
                message = "Signed well-known document verification is unavailable in this runtime.";
            }
            else
            {
                var result = await wellKnownVerifier.VerifyAsync(request, cancellationToken).ConfigureAwait(false);
                status = result.Status switch
                {
                    WellKnownHipDocumentVerificationStatus.Verified => VerificationStatus.Verified,
                    WellKnownHipDocumentVerificationStatus.NotAvailable => VerificationStatus.Pending,
                    _ => VerificationStatus.Unverified
                };
                message = result.Message;
            }
        }
        else if (method is VerificationMethod.HtmlFile or VerificationMethod.MetaTag)
        {
            if (!TokensMatch(request.Token, token))
            {
                status = VerificationStatus.Unverified;
                message = "The supplied verification challenge does not match the active domain claim.";
            }
            else
            {
                var check = await htmlVerifier.CheckAsync(normalized, method, request.Token, cancellationToken)
                    .ConfigureAwait(false);
                status = MapDnsCheckStatus(check.Status);
                message = check.Message;
            }
        }
        else
        {
            throw new ArgumentException("Unsupported domain verification method.", nameof(method));
        }

        var checkedAtUtc = clock.GetUtcNow();
        var attemptCount = checked(request.VerificationAttemptCount + 1);
        if (status != VerificationStatus.Verified && attemptCount >= lifecycle.MaximumVerificationAttempts)
        {
            status = VerificationStatus.Suspended;
            message = "The verification attempt limit was reached. Regenerate the challenge before retrying.";
        }
        var updated = request with
        {
            Status = status,
            VerifiedAtUtc = status == VerificationStatus.Verified ? checkedAtUtc : null,
            LastCheckedAtUtc = checkedAtUtc,
            LastCheckMessage = message,
            VerificationAttemptCount = attemptCount,
            ConsumedAtUtc = status == VerificationStatus.Verified ? checkedAtUtc : null,
            LastAttemptOutcome = status == VerificationStatus.Verified
                ? DomainVerificationAttemptOutcome.Succeeded
                : status == VerificationStatus.Pending ? DomainVerificationAttemptOutcome.Pending : DomainVerificationAttemptOutcome.Failed
        };
        return await TryApplyTransitionAsync(request, updated, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Retries a persisted DNS challenge using its stored token internally.
    /// </summary>
    public async Task<DomainVerificationRetryResult> RetryAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        if (!IsSupportedMethod(method))
        {
            throw new InvalidOperationException("Automated retry does not support this verification method.");
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken) ??
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        if (request.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot be retried.");
        }

        if (IsExpired(request))
        {
            var expired = await ExpireAsync(request, cancellationToken).ConfigureAwait(false);
            return new DomainVerificationRetryResult(
                expired,
                new DomainVerificationCheckResult(
                    normalized,
                    $"_hip.{normalized}",
                    DomainVerificationCheckStatus.PendingVerification,
                    clock.GetUtcNow(),
                    "The verification challenge expired. Issue a new challenge before checking DNS again."));
        }

        var check = method switch
        {
            VerificationMethod.DnsTxt => await CheckDnsTxtAsync(normalized, request.Token, cancellationToken).ConfigureAwait(false),
            VerificationMethod.WellKnownHipJson => await CheckWellKnownAsync(request, cancellationToken).ConfigureAwait(false),
            VerificationMethod.HtmlFile or VerificationMethod.MetaTag =>
                await htmlVerifier.CheckAsync(normalized, method, request.Token, cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidOperationException("Automated retry does not support this verification method.")
        };
        var status = MapDnsCheckStatus(check.Status);
        var updated = request with
        {
            Status = status,
            VerifiedAtUtc = status == VerificationStatus.Verified ? clock.GetUtcNow() : null,
            LastCheckedAtUtc = check.CheckedAtUtc,
            LastCheckMessage = check.Message
        };
        var persisted = await TryApplyTransitionAsync(request, updated, cancellationToken)
            .ConfigureAwait(false);
        return new DomainVerificationRetryResult(persisted, check);
    }

    private async Task<DomainVerificationCheckResult> CheckWellKnownAsync(
        DomainVerificationRequest request,
        CancellationToken cancellationToken)
    {
        var checkedAtUtc = clock.GetUtcNow();
        if (wellKnownVerifier is null)
        {
            return new DomainVerificationCheckResult(
                request.Domain,
                $"https://{request.Domain}/.well-known/hip.json",
                DomainVerificationCheckStatus.PendingVerification,
                checkedAtUtc,
                "Signed well-known document verification is unavailable in this runtime.");
        }

        var result = await wellKnownVerifier.VerifyAsync(request, cancellationToken).ConfigureAwait(false);
        return new DomainVerificationCheckResult(
            request.Domain,
            $"https://{request.Domain}/.well-known/hip.json",
            result.Status switch
            {
                WellKnownHipDocumentVerificationStatus.Verified => DomainVerificationCheckStatus.Verified,
                WellKnownHipDocumentVerificationStatus.Invalid => DomainVerificationCheckStatus.Invalid,
                _ => DomainVerificationCheckStatus.PendingVerification
            },
            checkedAtUtc,
            result.Message);
    }

    /// <summary>
    /// Revokes a persisted challenge and removes its verified timestamp.
    /// </summary>
    public async Task<DomainVerificationRequest> RevokeAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken) ??
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        return await RevokePersistedAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task<DomainVerificationRequest> RenewExpiredAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken) ??
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        if (request.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot issue another challenge.");
        }
        if (request.Status != VerificationStatus.Expired && IsExpired(request))
        {
            request = await ExpireAsync(request, cancellationToken).ConfigureAwait(false);
        }
        if (request.Status != VerificationStatus.Expired)
        {
            throw new InvalidOperationException("Only an expired verification challenge can be renewed.");
        }

        var now = clock.GetUtcNow();
        var renewed = request with
        {
            Token = DomainVerificationChallengeToken.Generate(),
            Status = VerificationStatus.Pending,
            CreatedAtUtc = now,
            VerifiedAtUtc = null,
            ExpiresAtUtc = now.Add(lifecycle.ChallengeLifetime),
            LastCheckedAtUtc = null,
            LastCheckMessage = "A new domain verification challenge was issued.",
            RevokedAtUtc = null,
            ChallengeVersion = checked(request.ChallengeVersion + 1),
            VerificationAttemptCount = 0,
            ConsumedAtUtc = null,
            LastAttemptOutcome = null
        };
        if (!await verificationRepository.TryUpdateAsync(request, renewed, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Domain verification state changed concurrently; reload before renewing.");
        }

        return renewed;
    }

    /// <inheritdoc />
    public async Task<DomainVerificationRequest> RegenerateAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken) ??
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        if (request.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot issue another challenge.");
        }

        var now = clock.GetUtcNow();
        var regenerated = request with
        {
            Token = DomainVerificationChallengeToken.Generate(),
            Status = VerificationStatus.Pending,
            CreatedAtUtc = now,
            VerifiedAtUtc = null,
            ExpiresAtUtc = now.Add(lifecycle.ChallengeLifetime),
            LastCheckedAtUtc = null,
            LastCheckMessage = "A replacement domain verification challenge was issued.",
            RevokedAtUtc = null,
            ChallengeVersion = checked(request.ChallengeVersion + 1),
            VerificationAttemptCount = 0,
            ConsumedAtUtc = null,
            LastAttemptOutcome = null
        };
        if (!await verificationRepository.TryUpdateAsync(request, regenerated, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Domain verification state changed concurrently; reload before regenerating.");
        }

        return regenerated;
    }
    private async Task<DomainVerificationRequest> TryApplyTransitionAsync(
        DomainVerificationRequest expected,
        DomainVerificationRequest updated,
        CancellationToken cancellationToken)
    {
        if (await verificationRepository.TryUpdateAsync(expected, updated, cancellationToken)
                .ConfigureAwait(false))
        {
            return updated;
        }

        var current = await verificationRepository.GetAsync(
                expected.Domain,
                expected.Method,
                cancellationToken)
            .ConfigureAwait(false) ??
            throw new InvalidOperationException("Domain verification state disappeared during a concurrent update.");
        if (current.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot be retried or reactivated.");
        }

        throw new InvalidOperationException("Domain verification state changed concurrently; retry the operation.");
    }

    private async Task<DomainVerificationRequest> RevokePersistedAsync(
        DomainVerificationRequest initial,
        CancellationToken cancellationToken)
    {
        var current = initial;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (current.Status == VerificationStatus.Revoked)
            {
                return current;
            }

            var now = clock.GetUtcNow();
            var revoked = current with
            {
                Status = VerificationStatus.Revoked,
                VerifiedAtUtc = null,
                LastCheckedAtUtc = now,
                LastCheckMessage = "Domain verification was revoked.",
                RevokedAtUtc = now
            };
            if (await verificationRepository.TryUpdateAsync(current, revoked, cancellationToken)
                    .ConfigureAwait(false))
            {
                return revoked;
            }

            current = await verificationRepository.GetAsync(
                    current.Domain,
                    current.Method,
                    cancellationToken)
                .ConfigureAwait(false) ??
                throw new InvalidOperationException("Domain verification state disappeared during revocation.");
        }

        throw new InvalidOperationException("Domain verification revocation could not win concurrent updates.");
    }

    /// <summary>
    /// Checks whether _hip.{domain} contains the expected HIP TXT verification value.
    /// </summary>
    /// <param name="domain">Domain whose _hip TXT record should be checked.</param>
    /// <param name="expectedToken">Expected raw verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the DNS lookup.</param>
    /// <returns>A status result that never echoes the expected token.</returns>
    public async Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var token = NormalizeExpectedToken(expectedToken);
        var recordName = $"_hip.{normalized}";
        var checkedAtUtc = clock.GetUtcNow();

        try
        {
            var records = await txtRecordResolver.ResolveTxtRecordsAsync(recordName, cancellationToken);
            var status = DetermineStatus(records, token);
            logger.LogInformation("HIP DNS verification checked {Domain} with status {Status}.", normalized, status);
            return new DomainVerificationCheckResult(normalized, recordName, status, checkedAtUtc, MessageFor(status));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "HIP DNS verification could not complete for {Domain}; token was not logged.", normalized);
            return new DomainVerificationCheckResult(
                normalized,
                recordName,
                DomainVerificationCheckStatus.PendingVerification,
                checkedAtUtc,
                "HIP could not complete the DNS check yet. Try again after DNS is available.");
        }
    }

    /// <summary>
    /// Converts a user-supplied token into the raw token value HIP expects inside the TXT record.
    /// </summary>
    /// <param name="expectedToken">Token supplied to the API or verification flow.</param>
    /// <returns>Raw token without the TXT prefix.</returns>
    private static string NormalizeExpectedToken(string expectedToken)
    {
        if (string.IsNullOrWhiteSpace(expectedToken))
        {
            throw new ArgumentException("Expected verification token is required.", nameof(expectedToken));
        }

        var trimmed = expectedToken.Trim();
        if (trimmed.Length > 256 || trimmed.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Expected verification token must be 1-256 non-whitespace characters.", nameof(expectedToken));
        }

        var rawToken = trimmed.StartsWith(VerificationPrefix, StringComparison.OrdinalIgnoreCase)
            ? trimmed[VerificationPrefix.Length..]
            : trimmed;

        if (string.IsNullOrWhiteSpace(rawToken))
        {
            throw new ArgumentException("Expected verification token is required.", nameof(expectedToken));
        }

        return rawToken;
    }

    /// <summary>
    /// Maps the DNS-specific check result onto the existing identity verification lifecycle.
    /// </summary>
    /// <param name="status">DNS TXT verification status.</param>
    /// <returns>Stored identity verification status.</returns>
    private static VerificationStatus MapDnsCheckStatus(DomainVerificationCheckStatus status) => status switch
    {
        DomainVerificationCheckStatus.Verified => VerificationStatus.Verified,
        DomainVerificationCheckStatus.Invalid => VerificationStatus.Unverified,
        _ => VerificationStatus.Pending
    };

    /// <summary>
    /// Determines the verification status from DNS TXT values without leaking expected token contents.
    /// </summary>
    /// <param name="records">TXT values returned by DNS.</param>
    /// <param name="expectedToken">Normalized raw expected token.</param>
    /// <returns>Verification status for the DNS evidence.</returns>
    private static DomainVerificationCheckStatus DetermineStatus(IReadOnlyCollection<string> records, string expectedToken)
    {
        if (records.Count == 0)
        {
            return DomainVerificationCheckStatus.NotConfigured;
        }

        var hipRecords = records
            .Select(NormalizeTxtValue)
            .Where(value => value.StartsWith(VerificationPrefix, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (hipRecords.Length == 0)
        {
            return DomainVerificationCheckStatus.NotConfigured;
        }

        return hipRecords.Any(value => TokensMatch(value[VerificationPrefix.Length..], expectedToken))
            ? DomainVerificationCheckStatus.Verified
            : DomainVerificationCheckStatus.Invalid;
    }

    /// <summary>
    /// Normalizes TXT records returned by different DNS clients by trimming quotes and whitespace.
    /// </summary>
    /// <param name="value">TXT value returned by the resolver.</param>
    /// <returns>Comparable TXT value.</returns>
    private static string NormalizeTxtValue(string value) => value.Trim().Trim('"');

    /// <summary>
    /// Compares tokens using ordinal comparison because DNS verification tokens are opaque identifiers.
    /// </summary>
    /// <param name="left">First token.</param>
    /// <param name="right">Second token.</param>
    /// <returns>True when the tokens match exactly.</returns>
    private static bool TokensMatch(string left, string right) =>
        DomainVerificationChallengeToken.Matches(left, right);

    private static bool IsSupportedMethod(VerificationMethod method) => method is
        VerificationMethod.DnsTxt or VerificationMethod.WellKnownHipJson or
        VerificationMethod.HtmlFile or VerificationMethod.MetaTag;

    /// <summary>
    /// Builds a plain-English status message that avoids exposing verification tokens.
    /// </summary>
    /// <param name="status">Verification status.</param>
    /// <returns>Human-readable explanation.</returns>
    private static string MessageFor(DomainVerificationCheckStatus status) => status switch
    {
        DomainVerificationCheckStatus.Verified => "HIP found the expected DNS TXT record for this domain.",
        DomainVerificationCheckStatus.Invalid => "HIP found a DNS TXT verification record, but it did not match the expected token.",
        DomainVerificationCheckStatus.PendingVerification => "HIP could not complete the DNS verification check yet.",
        _ => "HIP did not find a DNS TXT verification record for this domain."
    };

    private bool IsExpired(DomainVerificationRequest request) =>
        request.Status == VerificationStatus.Expired ||
        (request.Status != VerificationStatus.Verified &&
         (request.ExpiresAtUtc ?? request.CreatedAtUtc.Add(lifecycle.ChallengeLifetime)) <= clock.GetUtcNow());

    private async Task<DomainVerificationRequest> ExpireAsync(
        DomainVerificationRequest request,
        CancellationToken cancellationToken)
    {
        if (request.Status == VerificationStatus.Expired)
        {
            return request;
        }

        var expired = request with
        {
            Status = VerificationStatus.Expired,
            VerifiedAtUtc = null,
            ExpiresAtUtc = request.ExpiresAtUtc ?? request.CreatedAtUtc.Add(lifecycle.ChallengeLifetime),
            LastCheckedAtUtc = clock.GetUtcNow(),
            LastCheckMessage = "The domain verification challenge expired before it was completed."
        };
        return await TryApplyTransitionAsync(request, expired, cancellationToken).ConfigureAwait(false);
    }

    private static string StatusMessage(VerificationStatus status) => status switch
    {
        VerificationStatus.Verified => "Domain verification succeeded.",
        VerificationStatus.Unverified => "The verification evidence did not match the active challenge.",
        VerificationStatus.Expired => "The domain verification challenge expired.",
        _ => "Domain verification remains pending."
    };
}
