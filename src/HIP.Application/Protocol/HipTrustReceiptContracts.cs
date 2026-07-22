using HIP.Application.SiteSafety;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Application.Protocol;

/// <summary>Policy metadata and bounded lifetime applied by the server to newly issued receipts.</summary>
public sealed record HipTrustReceiptPolicy
{
    public static TimeSpan DefaultAllowedClockSkew { get; } = TimeSpan.FromMinutes(2);

    public static TimeSpan MaximumAllowedClockSkew { get; } = TimeSpan.FromMinutes(5);

    public static HipTrustReceiptPolicy Default { get; } = new(
        "site-safety-policy-v1",
        "site-safety-rules-v1",
        TimeSpan.FromHours(24),
        TimeSpan.FromMinutes(5),
        DefaultAllowedClockSkew);

    public HipTrustReceiptPolicy(
        string policyVersion,
        string ruleSetVersion,
        TimeSpan validityPeriod,
        TimeSpan maximumEvaluationAge)
        : this(
            policyVersion,
            ruleSetVersion,
            validityPeriod,
            maximumEvaluationAge,
            DefaultAllowedClockSkew)
    {
    }

    public HipTrustReceiptPolicy(
        string policyVersion,
        string ruleSetVersion,
        TimeSpan validityPeriod,
        TimeSpan maximumEvaluationAge,
        TimeSpan allowedClockSkew)
    {
        PolicyVersion = RequiredVersionToken(policyVersion, nameof(policyVersion));
        RuleSetVersion = RequiredVersionToken(ruleSetVersion, nameof(ruleSetVersion));
        if (validityPeriod <= TimeSpan.Zero || validityPeriod > TimeSpan.FromDays(7))
        {
            throw new ArgumentOutOfRangeException(
                nameof(validityPeriod),
                "HIP trust receipt validity must be between zero and seven days.");
        }

        if (maximumEvaluationAge <= TimeSpan.Zero || maximumEvaluationAge > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumEvaluationAge),
                "HIP trust receipt evaluation age must be between zero and one hour.");
        }

        if (allowedClockSkew < TimeSpan.Zero || allowedClockSkew > MaximumAllowedClockSkew)
        {
            throw new ArgumentOutOfRangeException(
                nameof(allowedClockSkew),
                $"HIP trust receipt clock skew must be between zero and {MaximumAllowedClockSkew.TotalMinutes} minutes.");
        }

        ValidityPeriod = validityPeriod;
        MaximumEvaluationAge = maximumEvaluationAge;
        AllowedClockSkew = allowedClockSkew;
    }

    public string PolicyVersion { get; }

    public string RuleSetVersion { get; }

    public TimeSpan ValidityPeriod { get; }

    public TimeSpan MaximumEvaluationAge { get; }

    public TimeSpan AllowedClockSkew { get; }

    private static string RequiredVersionToken(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > HipTrustReceipt.MaximumVersionTokenLength ||
            value.Any(character =>
                character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.' or ':')))
        {
            throw new ArgumentException(
                "HIP trust receipt policy versions must use bounded lowercase tokens.",
                parameterName);
        }

        return value;
    }
}

/// <summary>Bounded public request for issuing a receipt from one server-evaluated URL.</summary>
/// <param name="Url">Absolute public URL to evaluate. No caller-authored evidence is accepted.</param>
public sealed record HipTrustReceiptIssueRequest(string Url)
{
    /// <summary>Maximum JSON request size accepted before model binding.</summary>
    public const long MaximumRequestBodyBytes = 16_384;
}

/// <summary>Public signing metadata for a key whose private material remains inside managed key custody.</summary>
public sealed record HipManagedTrustReceiptSigningKey(
    string IssuerId,
    string KeyId,
    string Algorithm,
    SignatureAlgorithmFamily AlgorithmFamily);

/// <summary>Explicitly authorizes one managed key to sign HIP trust receipts.</summary>
public sealed record HipTrustReceiptAuthorizedSigner
{
    public HipTrustReceiptAuthorizedSigner(string issuerId, string keyId)
    {
        IssuerId = new HipProtocolIssuer(issuerId).Id;
        if (string.IsNullOrWhiteSpace(keyId) ||
            keyId.Length > HipProtocolSignature.MaximumKeyIdLength ||
            keyId.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new ArgumentException("Authorized receipt key IDs must be bounded protocol identifiers.", nameof(keyId));
        }

        KeyId = keyId;
    }

    public string IssuerId { get; }

    public string KeyId { get; }
}

/// <summary>
/// Fail-closed receipt-issuer allowlist. A verified identity key is not automatically authorized to issue HIP evaluations.
/// </summary>
public sealed class HipTrustReceiptIssuerPolicy
{
    public const int MaximumAuthorizedSigners = 64;
    public static HipTrustReceiptIssuerPolicy Default { get; } = new([]);
    private readonly HashSet<string> authorizedSignerKeys;

    public HipTrustReceiptIssuerPolicy(IEnumerable<HipTrustReceiptAuthorizedSigner> authorizedSigners)
    {
        ArgumentNullException.ThrowIfNull(authorizedSigners);
        var signers = authorizedSigners.ToArray();
        if (signers.Length > MaximumAuthorizedSigners || signers.Any(signer => signer is null))
        {
            throw new ArgumentOutOfRangeException(
                nameof(authorizedSigners),
                $"HIP trust receipt issuer policy supports at most {MaximumAuthorizedSigners} explicit signers.");
        }

        authorizedSignerKeys = new HashSet<string>(signers.Select(Key), StringComparer.Ordinal);
        if (authorizedSignerKeys.Count != signers.Length)
        {
            throw new ArgumentException("HIP trust receipt issuer policy cannot contain duplicate signers.", nameof(authorizedSigners));
        }

        AuthorizedSigners = Array.AsReadOnly(signers);
    }

    public IReadOnlyCollection<HipTrustReceiptAuthorizedSigner> AuthorizedSigners { get; }

    public bool IsAuthorized(string issuerId, string keyId) =>
        !string.IsNullOrWhiteSpace(issuerId) &&
        !string.IsNullOrWhiteSpace(keyId) &&
        authorizedSignerKeys.Contains(Key(issuerId, keyId));

    private static string Key(HipTrustReceiptAuthorizedSigner signer) => Key(signer.IssuerId, signer.KeyId);

    private static string Key(string issuerId, string keyId) => $"{issuerId}\n{keyId}";
}

/// <summary>
/// Server-side signing boundary. Implementations may use an HSM, cloud key service, or other managed custody;
/// private key material must never cross this interface.
/// </summary>
public interface IManagedTrustReceiptSigner
{
    Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken);

    Task<string> SignHashAsync(
        HipManagedTrustReceiptSigningKey signingKey,
        string contentHash,
        CancellationToken cancellationToken);
}

/// <summary>Secure default used when no managed receipt-signing integration is configured.</summary>
public sealed class UnavailableManagedTrustReceiptSigner : IManagedTrustReceiptSigner
{
    public Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException("Managed HIP trust receipt signing is unavailable.");
    }

    public Task<string> SignHashAsync(
        HipManagedTrustReceiptSigningKey signingKey,
        string contentHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException("Managed HIP trust receipt signing is unavailable.");
    }
}

public enum HipTrustReceiptRepositoryWriteStatus
{
    Unspecified = 0,
    Created,
    ExistingSame,
    Conflict
}

/// <summary>Immutable persistence projection for one exact signed receipt.</summary>
public sealed record HipStoredTrustReceipt(
    HipTrustReceipt Receipt,
    string ReceiptJson,
    string ReceiptDigest,
    string SourceEvaluationDigest);

public sealed record HipTrustReceiptRepositoryWriteResult(
    HipTrustReceiptRepositoryWriteStatus Status,
    HipStoredTrustReceipt? StoredReceipt = null);

/// <summary>Insert-only trust receipt storage with unique receipt and authoritative-evaluation identities.</summary>
public interface IHipTrustReceiptRepository
{
    Task<HipStoredTrustReceipt?> GetByIdAsync(string receiptId, CancellationToken cancellationToken);

    Task<HipStoredTrustReceipt?> GetByRelatedEvaluationIdAsync(
        string relatedEvaluationId,
        CancellationToken cancellationToken);

    Task<HipTrustReceiptRepositoryWriteResult> TryCreateAsync(
        HipStoredTrustReceipt receipt,
        CancellationToken cancellationToken);
}

public enum HipTrustReceiptVerificationStatus
{
    Unspecified = 0,
    Verified,
    MalformedReceipt,
    UnsupportedVersion,
    WrongDocumentType,
    Expired,
    IssuerNotAuthorized,
    IssuerNotFound,
    IssuerNotVerified,
    IssuerSuspended,
    IssuerRevoked,
    IssuerBindingMismatch,
    KeyNotFound,
    KeyNotValidAtIssuedTime,
    KeyRevoked,
    SignatureMetadataMismatch,
    ProviderUnavailable,
    InvalidSignature,
    VerificationStateUnavailable,
    TimestampOutsideTolerance,
    ValidityWindowExceeded
}

public sealed record HipTrustReceiptVerificationResult(
    HipTrustReceiptVerificationStatus Status,
    HipTrustReceipt? Receipt = null,
    string? VerifiedIssuerId = null,
    string? VerifiedKeyId = null)
{
    public bool IsVerified => Status == HipTrustReceiptVerificationStatus.Verified;

    public bool EstablishesSafetyOrReputationBySignatureAlone => false;
}

public interface IHipTrustReceiptVerificationService
{
    Task<HipTrustReceiptVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> utf8Receipt,
        CancellationToken cancellationToken);
}

public enum HipTrustReceiptIssueStatus
{
    Unspecified = 0,
    Issued,
    Existing,
    InvalidEvaluation,
    SignerUnavailable,
    SignerNotAuthorized,
    VerificationFailed,
    PersistenceUnavailable,
    Conflict
}

public sealed record HipTrustReceiptIssueResult(
    HipTrustReceiptIssueStatus Status,
    HipTrustReceipt? Receipt = null)
{
    public bool IsSuccess => Status is HipTrustReceiptIssueStatus.Issued or HipTrustReceiptIssueStatus.Existing;
}

/// <summary>Issues receipts only from HIP's completed server-authoritative Site Safety evaluation.</summary>
public interface IHipTrustReceiptIssuanceService
{
    Task<HipTrustReceiptIssueResult> IssueAsync(
        SiteSafetyScanResult authoritativeEvaluation,
        CancellationToken cancellationToken);
}

public interface IHipTrustReceiptEvidenceDigestService
{
    HipContentDigest Compute(
        SiteSafetyScanResult authoritativeEvaluation,
        IReadOnlyCollection<string> reasonCodes,
        IReadOnlyCollection<string> warningCodes,
        HipTrustReceiptPolicy policy);
}
