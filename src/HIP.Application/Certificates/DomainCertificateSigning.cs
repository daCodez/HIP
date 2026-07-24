using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Protocol;
using HIP.Application.PublicLookup;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Application.Certificates;

public enum DomainCertificatePublicRiskClassification { Unknown, Low, Medium, High, Critical }

public enum DomainCertificateSigningStatus
{
    InvalidRequest,
    Ineligible,
    ReviewRequired,
    SignerUnavailable,
    SignerNotAuthorized,
    VerificationFailed,
    Signed
}

public sealed record DomainCertificateAuthorizedSigner(string AuthorityId, string KeyId);

/// <summary>Fail-closed allowlist for managed keys authorized to sign domain certificates.</summary>
public sealed class DomainCertificateSigningAuthorityPolicy
{
    private readonly HashSet<string> authorized;

    public DomainCertificateSigningAuthorityPolicy(IEnumerable<DomainCertificateAuthorizedSigner> signers)
    {
        ArgumentNullException.ThrowIfNull(signers);
        var values = signers.ToArray();
        if (values.Length > 64 || values.Any(value => value is null))
        {
            throw new ArgumentException("Certificate signing authority policy is invalid.", nameof(signers));
        }

        authorized = new HashSet<string>(values.Select(value => Key(
            new HipProtocolIssuer(value.AuthorityId).Id,
            ValidateKeyId(value.KeyId))), StringComparer.Ordinal);
        if (authorized.Count != values.Length)
        {
            throw new ArgumentException("Certificate signing authority policy contains duplicates.", nameof(signers));
        }
    }

    public bool IsAuthorized(string authorityId, string keyId) =>
        !string.IsNullOrWhiteSpace(authorityId) &&
        !string.IsNullOrWhiteSpace(keyId) &&
        authorized.Contains(Key(authorityId, keyId));

    private static string ValidateKeyId(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId) || keyId.Length > 128 || keyId.Any(char.IsControl))
        {
            throw new ArgumentException("Certificate signing key ID is invalid.", nameof(keyId));
        }
        return keyId;
    }

    private static string Key(string authorityId, string keyId) => $"{authorityId}\n{keyId}";
}

public sealed record DomainCertificateSigningDraft(
    string CertificateId,
    int CertificateVersion,
    string Domain,
    DomainCertificateLevel Level,
    string? PublicDisplayName,
    string? PublicOrganizationName,
    string? RegistrantPublicKeyId,
    IReadOnlyCollection<VerificationMethod> CompletedVerificationMethods,
    DomainCertificatePublicRiskClassification PublicRiskClassification,
    IReadOnlyCollection<string> PublicFindingCodes,
    string RevocationStatusUrl,
    string PublicCertificateUrl,
    DateTimeOffset LastVerificationAtUtc,
    DateTimeOffset? LastMonitoringAtUtc,
    DomainCertificatePolicyEvaluationResult Evaluation);

public sealed record DomainTrustCertificatePayload(
    string CertificateId,
    int CertificateVersion,
    string PolicyVersion,
    string Domain,
    string? PublicDisplayName,
    string? PublicOrganizationName,
    DomainCertificateLevel Level,
    DomainCertificateStatus Status,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset LastVerificationAtUtc,
    DateTimeOffset? LastMonitoringAtUtc,
    string? RegistrantPublicKeyId,
    IReadOnlyCollection<VerificationMethod> CompletedVerificationMethods,
    DomainCertificatePublicRiskClassification PublicRiskClassification,
    IReadOnlyCollection<string> PublicFindingCodes,
    string RevocationStatusUrl,
    string PublicCertificateUrl);

public sealed record DomainTrustCertificateSignature(
    string AuthorityId,
    string KeyId,
    string Algorithm,
    SignatureAlgorithmFamily AlgorithmFamily,
    string Canonicalization,
    string Value);

public sealed record SignedDomainTrustCertificate(
    DomainTrustCertificatePayload Payload,
    DomainTrustCertificateSignature Signature);

public sealed record DomainCertificateSigningResult(
    DomainCertificateSigningStatus Status,
    SignedDomainTrustCertificate? Certificate = null);

public interface IDomainCertificateSigningService
{
    Task<DomainCertificateSigningResult> SignAsync(
        DomainCertificateSigningDraft draft,
        CancellationToken cancellationToken);
}

public static class DomainTrustCertificateJson
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static string Serialize(SignedDomainTrustCertificate certificate) =>
        JsonSerializer.Serialize(certificate, Options);

    /// <summary>Parses a signed public certificate using the stable certificate JSON contract.</summary>
    public static SignedDomainTrustCertificate Deserialize(string certificateJson) =>
        JsonSerializer.Deserialize<SignedDomainTrustCertificate>(certificateJson, Options)
        ?? throw new JsonException("The signed domain certificate JSON is empty.");

    public static byte[] SigningPayload(DomainTrustCertificatePayload payload) =>
        JsonSerializer.SerializeToUtf8Bytes(payload, Options);

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}

/// <summary>Signs only eligible, normalized certificates and verifies the result before returning it.</summary>
public sealed class DomainCertificateSigningService(
    IManagedTrustReceiptSigner managedSigner,
    IHipSignedDocumentVerifier signedDocumentVerifier,
    ICanonicalJsonService canonicalJsonService,
    DomainCertificatePolicy policy,
    DomainCertificateSigningAuthorityPolicy authorityPolicy,
    TimeProvider timeProvider) : IDomainCertificateSigningService
{
    private readonly IManagedTrustReceiptSigner signer = managedSigner;
    private readonly IHipSignedDocumentVerifier verifier = signedDocumentVerifier;
    private readonly ICanonicalJsonService canonicalizer = canonicalJsonService;
    private readonly DomainCertificatePolicy certificatePolicy = policy.Validate();
    private readonly DomainCertificateSigningAuthorityPolicy authorities = authorityPolicy;
    private readonly TimeProvider clock = timeProvider;

    public async Task<DomainCertificateSigningResult> SignAsync(
        DomainCertificateSigningDraft draft,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (draft is null)
        {
            return Result(DomainCertificateSigningStatus.InvalidRequest);
        }
        if (draft.Evaluation.Decision == DomainCertificatePolicyDecision.Ineligible)
        {
            return Result(DomainCertificateSigningStatus.Ineligible);
        }
        if (draft.Evaluation.Decision == DomainCertificatePolicyDecision.RequiresReview)
        {
            return Result(DomainCertificateSigningStatus.ReviewRequired);
        }

        DomainTrustCertificatePayload payload;
        try
        {
            payload = Prepare(draft, clock.GetUtcNow());
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return Result(DomainCertificateSigningStatus.InvalidRequest);
        }

        HipManagedTrustReceiptSigningKey key;
        try
        {
            key = await signer.GetSigningKeyAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateSigningStatus.SignerUnavailable);
        }

        if (!authorities.IsAuthorized(key.IssuerId, key.KeyId))
        {
            return Result(DomainCertificateSigningStatus.SignerNotAuthorized);
        }

        SignedDomainTrustCertificate certificate;
        try
        {
            var payloadJson = DomainTrustCertificateJson.SigningPayload(payload);
            var canonical = canonicalizer.Canonicalize(payloadJson);
            var contentHash = Sha256(canonical);
            var signatureValue = await signer.SignHashAsync(key, contentHash, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(signatureValue) || signatureValue.Length > 32_768)
            {
                return Result(DomainCertificateSigningStatus.SignerUnavailable);
            }
            certificate = new SignedDomainTrustCertificate(
                payload,
                new DomainTrustCertificateSignature(
                    key.IssuerId,
                    key.KeyId,
                    key.Algorithm,
                    key.AlgorithmFamily,
                    HipProtocolSignature.Rfc8785Canonicalization,
                    signatureValue));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateSigningStatus.SignerUnavailable);
        }

        HipSignedDocumentVerificationResult verification;
        try
        {
            verification = await verifier.VerifyAsync(
                new HipSignedDocumentVerificationRequest(
                    certificate.Signature.AuthorityId,
                    certificate.Signature.KeyId,
                    certificate.Signature.Algorithm,
                    certificate.Signature.AlgorithmFamily,
                    certificate.Signature.Canonicalization,
                    certificate.Signature.Value,
                    certificate.Payload.IssuedAtUtc,
                    DomainTrustCertificateJson.SigningPayload(certificate.Payload)),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return Result(DomainCertificateSigningStatus.VerificationFailed);
        }

        return verification.IsVerified
            ? new DomainCertificateSigningResult(DomainCertificateSigningStatus.Signed, certificate)
            : Result(DomainCertificateSigningStatus.VerificationFailed);
    }

    private DomainTrustCertificatePayload Prepare(DomainCertificateSigningDraft draft, DateTimeOffset issuedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(draft.Evaluation);
        ArgumentNullException.ThrowIfNull(draft.CompletedVerificationMethods);
        ArgumentNullException.ThrowIfNull(draft.PublicFindingCodes);
        var domain = DomainInputValidator.ValidateAndNormalize(draft.Domain);
        if (!string.Equals(domain, draft.Domain, StringComparison.Ordinal) ||
            draft.Evaluation.Decision != DomainCertificatePolicyDecision.Eligible ||
            !string.Equals(draft.Evaluation.Domain, domain, StringComparison.Ordinal) ||
            draft.Evaluation.RequestedLevel != draft.Level ||
            !string.Equals(draft.Evaluation.PolicyVersion, certificatePolicy.Version, StringComparison.Ordinal) ||
            draft.CertificateVersion < 1 ||
            issuedAtUtc.Offset != TimeSpan.Zero ||
            draft.LastVerificationAtUtc.Offset != TimeSpan.Zero ||
            draft.LastVerificationAtUtc > issuedAtUtc ||
            draft.Evaluation.EvaluatedAtUtc.Offset != TimeSpan.Zero ||
            draft.Evaluation.EvaluatedAtUtc > issuedAtUtc)
        {
            throw new ArgumentException("Certificate signing draft does not match its policy evaluation.", nameof(draft));
        }

        ValidateToken(draft.CertificateId, 128, nameof(draft.CertificateId));
        ValidateOptionalText(draft.PublicDisplayName, 200, nameof(draft.PublicDisplayName));
        ValidateOptionalText(draft.PublicOrganizationName, 200, nameof(draft.PublicOrganizationName));
        ValidateOptionalText(draft.RegistrantPublicKeyId, 128, nameof(draft.RegistrantPublicKeyId));
        var methods = draft.CompletedVerificationMethods.Distinct().Order().ToArray();
        if (methods.Length == 0)
        {
            throw new ArgumentException("Completed verification methods are required.", nameof(draft));
        }
        var findings = draft.PublicFindingCodes.Select(code =>
        {
            ValidateToken(code, 80, nameof(draft.PublicFindingCodes));
            return code;
        }).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var revocationUrl = ValidateHttpsUrl(draft.RevocationStatusUrl, nameof(draft.RevocationStatusUrl));
        var certificateUrl = ValidateHttpsUrl(draft.PublicCertificateUrl, nameof(draft.PublicCertificateUrl));
        if (draft.LastMonitoringAtUtc is { } monitoredAt &&
            (monitoredAt.Offset != TimeSpan.Zero || monitoredAt > issuedAtUtc))
        {
            throw new ArgumentException("Last monitoring timestamp is invalid.", nameof(draft));
        }

        var lifetime = draft.Level == DomainCertificateLevel.Registered
            ? certificatePolicy.RegisteredLifetime
            : certificatePolicy.VerifiedLifetime;
        return new DomainTrustCertificatePayload(
            draft.CertificateId, draft.CertificateVersion, certificatePolicy.Version, domain,
            draft.PublicDisplayName, draft.PublicOrganizationName, draft.Level, DomainCertificateStatus.Active,
            issuedAtUtc, issuedAtUtc.Add(lifetime), draft.LastVerificationAtUtc, draft.LastMonitoringAtUtc,
            draft.RegistrantPublicKeyId, methods, draft.PublicRiskClassification, findings,
            revocationUrl, certificateUrl);
    }

    private static string ValidateHttpsUrl(string value, string parameterName)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) || uri.Port != 443 || !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) || value.Length > 512)
        {
            throw new ArgumentException(
                "Public certificate URLs must be bounded HTTPS URLs without credentials or query data.",
                parameterName);
        }

        return uri.AbsoluteUri;
    }

    private static void ValidateToken(string value, int maximumLength, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > maximumLength ||
            value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':')))
        {
            throw new ArgumentException("Public certificate token is invalid.", parameterName);
        }
    }

    private static void ValidateOptionalText(string? value, int maximumLength, string parameterName)
    {
        if (value is not null &&
            (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl)))
        {
            throw new ArgumentException("Public certificate text is invalid.", parameterName);
        }
    }

    private static string Sha256(ReadOnlySpan<byte> content) =>
        Convert.ToHexStringLower(SHA256.HashData(content));

    private static DomainCertificateSigningResult Result(DomainCertificateSigningStatus status) =>
        new(status);
}
