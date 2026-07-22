using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Application.Protocol;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Application.Identity;

public interface IWellKnownHipDocumentFetcher
{
    Task<HipWellKnownDocument?> FetchAsync(string normalizedDomain, CancellationToken cancellationToken);
}

public sealed class UnavailableWellKnownHipDocumentFetcher : IWellKnownHipDocumentFetcher
{
    public Task<HipWellKnownDocument?> FetchAsync(string normalizedDomain, CancellationToken cancellationToken) =>
        Task.FromResult<HipWellKnownDocument?>(null);
}

public enum WellKnownHipDocumentVerificationStatus
{
    Verified,
    NotAvailable,
    Invalid
}

public sealed record WellKnownHipDocumentVerificationResult(
    WellKnownHipDocumentVerificationStatus Status,
    string Message);

public interface IWellKnownHipDocumentVerifier
{
    Task<WellKnownHipDocumentVerificationResult> VerifyAsync(
        DomainVerificationRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Verifies domain control and registered-key possession from a bounded, remotely fetched HIP document.
/// This result establishes neither safety nor reputation.
/// </summary>
public sealed class WellKnownHipDocumentVerifier(
    IWellKnownHipDocumentFetcher fetcher,
    IWebsiteIdentityRepository websiteIdentities,
    ICanonicalJsonService canonicalizer,
    IHipSignatureProviderFactory providerFactory,
    SignatureProviderRuntimePolicy providerPolicy,
    TimeProvider? timeProvider = null) : IWellKnownHipDocumentVerifier
{
    private static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(5);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<WellKnownHipDocumentVerificationResult> VerifyAsync(
        DomainVerificationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Method != VerificationMethod.WellKnownHipJson)
        {
            throw new ArgumentException("A well-known verifier requires a well-known challenge.", nameof(request));
        }

        var domain = DomainInputValidator.ValidateAndNormalize(request.Domain);
        HipWellKnownDocument? document;
        try
        {
            document = await fetcher.FetchAsync(domain, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(WellKnownHipDocumentVerificationStatus.NotAvailable,
                "HIP could not retrieve the well-known document yet.");
        }

        if (document is null)
        {
            return Result(WellKnownHipDocumentVerificationStatus.NotAvailable,
                "The well-known HIP document is not available yet.");
        }

        WebsiteIdentity? registered;
        try
        {
            registered = await websiteIdentities.GetAsync(domain, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            return Result(WellKnownHipDocumentVerificationStatus.NotAvailable,
                "HIP could not load the registered website identity.");
        }

        if (registered is null || !DocumentMatchesRegistration(document, registered, request, clock.GetUtcNow()))
        {
            return Result(WellKnownHipDocumentVerificationStatus.Invalid,
                "The well-known HIP document does not match the active domain claim and registered identity.");
        }

        var signature = document.Signature!;
        var key = registered.PublicKeys.Single(candidate =>
            string.Equals(candidate.KeyId, signature.KeyId, StringComparison.Ordinal));
        try
        {
            var provider = providerFactory.GetRequiredProvider(
                signature.Algorithm,
                SignatureProviderOperations.Verify,
                providerPolicy);
            var canonicalPayload = CreateCanonicalSigningPayload(document, canonicalizer);
            var contentHash = $"sha256:{Convert.ToHexString(SHA256.HashData(canonicalPayload)).ToLowerInvariant()}";
            if (!provider.VerifySignature(contentHash, signature.Value, key.PublicKey))
            {
                return Result(WellKnownHipDocumentVerificationStatus.Invalid,
                    "The well-known HIP document signature is invalid.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(WellKnownHipDocumentVerificationStatus.Invalid,
                "The well-known HIP document signature could not be verified.");
        }

        return Result(WellKnownHipDocumentVerificationStatus.Verified,
            "The well-known HIP document proves domain control and registered-key possession; safety is evaluated separately.");
    }

    public static byte[] CreateCanonicalSigningPayload(
        HipWellKnownDocument document,
        ICanonicalJsonService canonicalizer)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(canonicalizer);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = document.SchemaVersion,
            domain = document.Domain,
            hipIdentityId = document.HipIdentityId,
            publicKeys = document.PublicKeys
                .OrderBy(key => key.KeyId, StringComparer.Ordinal)
                .Select(key => new { keyId = key.KeyId, algorithm = key.Algorithm, publicKey = key.PublicKey })
                .ToArray(),
            verificationChallenge = document.VerificationChallenge,
            issuedAtUtc = document.IssuedAtUtc,
            expiresAtUtc = document.ExpiresAtUtc
        });
        return canonicalizer.Canonicalize(payload);
    }

    private static bool DocumentMatchesRegistration(
        HipWellKnownDocument document,
        WebsiteIdentity registered,
        DomainVerificationRequest request,
        DateTimeOffset now)
    {
        string normalizedDocumentDomain;
        try
        {
            normalizedDocumentDomain = DomainInputValidator.ValidateAndNormalize(document.Domain);
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (!string.Equals(document.SchemaVersion, "1", StringComparison.Ordinal) ||
            !string.Equals(normalizedDocumentDomain, request.Domain, StringComparison.Ordinal) ||
            !string.Equals(document.Domain, normalizedDocumentDomain, StringComparison.Ordinal) ||
            !string.Equals(document.HipIdentityId, registered.HipIdentityId, StringComparison.Ordinal) ||
            !FixedTimeEquals(document.VerificationChallenge, request.Token) ||
            document.IssuedAtUtc < request.CreatedAtUtc ||
            document.IssuedAtUtc > now.Add(MaximumClockSkew) ||
            request.ExpiresAtUtc is null ||
            document.ExpiresAtUtc is null ||
            document.ExpiresAtUtc <= now ||
            document.ExpiresAtUtc > request.ExpiresAtUtc ||
            document.Signature is null ||
            !string.Equals(document.Signature.Scope, HipProtocolSignature.OriginAndIntegrityScope, StringComparison.Ordinal) ||
            !string.Equals(document.Signature.Canonicalization, HipProtocolSignature.Rfc8785Canonicalization, StringComparison.Ordinal))
        {
            return false;
        }

        var documentKeys = document.PublicKeys.OrderBy(key => key.KeyId, StringComparer.Ordinal).ToArray();
        var registeredKeys = registered.PublicKeys.OrderBy(key => key.KeyId, StringComparer.Ordinal).ToArray();
        return documentKeys.SequenceEqual(registeredKeys) &&
            registeredKeys.Any(key =>
                string.Equals(key.KeyId, document.Signature.KeyId, StringComparison.Ordinal) &&
                string.Equals(key.Algorithm, document.Signature.Algorithm, StringComparison.Ordinal));
    }

    private static bool FixedTimeEquals(string? left, string right)
    {
        if (left is null)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(left),
            Encoding.UTF8.GetBytes(right));
    }

    private static WellKnownHipDocumentVerificationResult Result(
        WellKnownHipDocumentVerificationStatus status,
        string message) => new(status, message);
}
