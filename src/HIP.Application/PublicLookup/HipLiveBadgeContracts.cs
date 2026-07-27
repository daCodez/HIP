using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Certificates;
using HIP.Domain.Certificates;
using HIP.Domain.Protocol;
using HIP.Domain.Risk;

namespace HIP.Application.PublicLookup;

/// <summary>Bounded lifetime and clock policy for signed live badge documents.</summary>
public sealed record HipLiveBadgePolicy
{
    public static HipLiveBadgePolicy Default { get; } = new(
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(2));

    public HipLiveBadgePolicy(TimeSpan validityPeriod, TimeSpan allowedClockSkew)
    {
        if (validityPeriod <= TimeSpan.Zero || validityPeriod > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(validityPeriod),
                "HIP live badge validity must be between zero and one hour.");
        }

        if (allowedClockSkew < TimeSpan.Zero || allowedClockSkew > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(
                nameof(allowedClockSkew),
                "HIP live badge clock skew must be between zero and five minutes.");
        }

        ValidityPeriod = validityPeriod;
        AllowedClockSkew = allowedClockSkew;
    }

    public TimeSpan ValidityPeriod { get; }

    public TimeSpan AllowedClockSkew { get; }
}

/// <summary>Only public display data derived by HIP can enter the signed badge boundary.</summary>
public sealed record HipLiveBadgeSigningRequest(
    string Domain,
    int Score,
    RiskStatus Status,
    bool VerifiedDomain,
    string IdentityVerificationStatus,
    string VerifiedMeaning,
    DateTimeOffset LastCheckedUtc,
    HipLiveBadgeCertificateState? Certificate = null,
    int? DisplayScore = null,
    string ScorePresentation = PublicEvidencePresentation.ScoreWithheldInsufficientEvidence,
    string EvidenceCoverage = PublicEvidencePresentation.CoverageInsufficient,
    string EvidenceConfidence = PublicEvidencePresentation.ConfidenceNone);

/// <summary>Public certificate facts independently verified by HIP and bound into the short-lived badge signature.</summary>
public sealed record HipLiveBadgeCertificateState
{
    [JsonConstructor]
    public HipLiveBadgeCertificateState(
        string certificateId,
        string domain,
        DomainCertificateLevel level,
        DomainCertificateStatus status,
        PublicDomainCertificateSignatureStatus signatureStatus,
        DateTimeOffset expiresAtUtc,
        string publicCertificateUrl,
        bool isActive)
    {
        if (string.IsNullOrWhiteSpace(certificateId) ||
            certificateId.Length > 128 ||
            certificateId.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':')))
        {
            throw new ArgumentException("HIP badge certificate identifier is invalid.", nameof(certificateId));
        }

        var normalizedDomain = DomainInputValidator.ValidateAndNormalize(domain);
        if (!string.Equals(domain, normalizedDomain, StringComparison.Ordinal) ||
            !Enum.IsDefined(level) ||
            !Enum.IsDefined(status) ||
            !Enum.IsDefined(signatureStatus) ||
            expiresAtUtc.Offset != TimeSpan.Zero ||
            !Uri.TryCreate(publicCertificateUrl, UriKind.Absolute, out var publicUrl) ||
            publicUrl.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(publicUrl.UserInfo) ||
            !string.IsNullOrEmpty(publicUrl.Query) ||
            !string.IsNullOrEmpty(publicUrl.Fragment) ||
            (isActive && (status != DomainCertificateStatus.Active ||
                          signatureStatus != PublicDomainCertificateSignatureStatus.Verified)))
        {
            throw new ArgumentException("HIP badge certificate state is invalid.", nameof(domain));
        }

        CertificateId = certificateId;
        Domain = normalizedDomain;
        Level = level;
        Status = status;
        SignatureStatus = signatureStatus;
        ExpiresAtUtc = expiresAtUtc;
        PublicCertificateUrl = publicUrl.AbsoluteUri;
        IsActive = isActive;
    }

    [JsonPropertyName("certificateId")]
    [JsonPropertyOrder(0)]
    public string CertificateId { get; }

    [JsonPropertyName("domain")]
    [JsonPropertyOrder(1)]
    public string Domain { get; }

    [JsonPropertyName("level")]
    [JsonPropertyOrder(2)]
    [JsonConverter(typeof(JsonStringEnumConverter<DomainCertificateLevel>))]
    public DomainCertificateLevel Level { get; }

    [JsonPropertyName("status")]
    [JsonPropertyOrder(3)]
    [JsonConverter(typeof(JsonStringEnumConverter<DomainCertificateStatus>))]
    public DomainCertificateStatus Status { get; }

    [JsonPropertyName("signatureStatus")]
    [JsonPropertyOrder(4)]
    [JsonConverter(typeof(JsonStringEnumConverter<PublicDomainCertificateSignatureStatus>))]
    public PublicDomainCertificateSignatureStatus SignatureStatus { get; }

    [JsonPropertyName("expiresAtUtc")]
    [JsonPropertyOrder(5)]
    public DateTimeOffset ExpiresAtUtc { get; }

    [JsonPropertyName("publicCertificateUrl")]
    [JsonPropertyOrder(6)]
    public string PublicCertificateUrl { get; }

    [JsonPropertyName("isActive")]
    [JsonPropertyOrder(7)]
    public bool IsActive { get; }
}
/// <summary>Versioned public facts cryptographically bound into a live badge.</summary>
public sealed record HipLiveBadgePayload
{
    public const string LiveBadgeDocumentType = "hip-live-badge";
    public const int MaximumTextLength = 512;

    [JsonConstructor]
    public HipLiveBadgePayload(
        string documentType,
        string version,
        string domain,
        int score,
        RiskStatus status,
        bool verifiedDomain,
        string identityVerificationStatus,
        string verifiedMeaning,
        DateTimeOffset lastCheckedUtc,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        HipLiveBadgeCertificateState? certificate = null,
        int? displayScore = null,
        string scorePresentation = PublicEvidencePresentation.ScoreWithheldInsufficientEvidence,
        string evidenceCoverage = PublicEvidencePresentation.CoverageInsufficient,
        string evidenceConfidence = PublicEvidencePresentation.ConfidenceNone)
    {
        if (!string.Equals(documentType, LiveBadgeDocumentType, StringComparison.Ordinal))
        {
            throw new ArgumentException("HIP live badge document type is invalid.", nameof(documentType));
        }

        if (!string.Equals(version, HipProtocolVersion.CurrentValue, StringComparison.Ordinal))
        {
            throw new NotSupportedException($"HIP live badge version '{version}' is unsupported.");
        }

        var normalizedDomain = DomainInputValidator.ValidateAndNormalize(domain);
        if (!string.Equals(domain, normalizedDomain, StringComparison.Ordinal))
        {
            throw new ArgumentException("HIP live badge domains must already be normalized.", nameof(domain));
        }

        if (score is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(score), "HIP live badge scores must be between 0 and 100.");
        }

        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), "HIP live badge status is unsupported.");
        }

        DocumentType = documentType;
        Version = version;
        Domain = normalizedDomain;
        Score = score;
        Status = status;
        VerifiedDomain = verifiedDomain;
        IdentityVerificationStatus = RequiredPublicText(
            identityVerificationStatus,
            nameof(identityVerificationStatus));
        VerifiedMeaning = RequiredPublicText(verifiedMeaning, nameof(verifiedMeaning));
        LastCheckedUtc = RequiredUtcMillisecond(lastCheckedUtc, nameof(lastCheckedUtc));
        IssuedAtUtc = RequiredUtcMillisecond(issuedAtUtc, nameof(issuedAtUtc));
        ExpiresAtUtc = RequiredUtcMillisecond(expiresAtUtc, nameof(expiresAtUtc));
        Certificate = certificate;
        ScorePresentation = RequiredPresentationValue(
            scorePresentation,
            nameof(scorePresentation),
            PublicEvidencePresentation.ScoreAvailable,
            PublicEvidencePresentation.ScoreWithheldInsufficientEvidence);
        EvidenceCoverage = RequiredPresentationValue(
            evidenceCoverage,
            nameof(evidenceCoverage),
            PublicEvidencePresentation.CoverageInsufficient,
            PublicEvidencePresentation.CoverageSufficient);
        EvidenceConfidence = RequiredPresentationValue(
            evidenceConfidence,
            nameof(evidenceConfidence),
            PublicEvidencePresentation.ConfidenceNone,
            PublicEvidencePresentation.ConfidenceMedium,
            PublicEvidencePresentation.ConfidenceHigh);
        DisplayScore = PublicEvidencePresentation.DisplayScore(ScorePresentation, score);
        if (displayScore != DisplayScore)
        {
            throw new ArgumentException("HIP live badge display score does not match its presentation state.", nameof(displayScore));
        }

        if (ScorePresentation == PublicEvidencePresentation.ScoreAvailable &&
            (EvidenceCoverage != PublicEvidencePresentation.CoverageSufficient ||
             EvidenceConfidence == PublicEvidencePresentation.ConfidenceNone))
        {
            throw new ArgumentException("Available HIP scores require sufficient authenticated evidence.", nameof(scorePresentation));
        }

        if (ScorePresentation == PublicEvidencePresentation.ScoreWithheldInsufficientEvidence &&
            EvidenceCoverage != PublicEvidencePresentation.CoverageInsufficient)
        {
            throw new ArgumentException("Withheld HIP scores must report insufficient evidence coverage.", nameof(evidenceCoverage));
        }

        if (LastCheckedUtc > IssuedAtUtc)
        {
            throw new ArgumentException("HIP live badge data cannot be newer than its issuance time.", nameof(lastCheckedUtc));
        }

        if (ExpiresAtUtc <= IssuedAtUtc)
        {
            throw new ArgumentException("HIP live badge expiry must be later than issuance.", nameof(expiresAtUtc));
        }
    }

    [JsonPropertyName("documentType")]
    [JsonPropertyOrder(0)]
    public string DocumentType { get; }

    [JsonPropertyName("version")]
    [JsonPropertyOrder(1)]
    public string Version { get; }

    [JsonPropertyName("domain")]
    [JsonPropertyOrder(2)]
    public string Domain { get; }

    [JsonPropertyName("score")]
    [JsonPropertyOrder(3)]
    public int Score { get; }

    [JsonPropertyName("status")]
    [JsonPropertyOrder(4)]
    [JsonConverter(typeof(JsonStringEnumConverter<RiskStatus>))]
    public RiskStatus Status { get; }

    [JsonPropertyName("verifiedDomain")]
    [JsonPropertyOrder(5)]
    public bool VerifiedDomain { get; }

    [JsonPropertyName("identityVerificationStatus")]
    [JsonPropertyOrder(6)]
    public string IdentityVerificationStatus { get; }

    [JsonPropertyName("verifiedMeaning")]
    [JsonPropertyOrder(7)]
    public string VerifiedMeaning { get; }

    [JsonPropertyName("lastCheckedUtc")]
    [JsonPropertyOrder(8)]
    public DateTimeOffset LastCheckedUtc { get; }

    [JsonPropertyName("issuedAtUtc")]
    [JsonPropertyOrder(9)]
    public DateTimeOffset IssuedAtUtc { get; }

    [JsonPropertyName("expiresAtUtc")]
    [JsonPropertyOrder(10)]
    public DateTimeOffset ExpiresAtUtc { get; }

    [JsonPropertyName("certificate")]
    [JsonPropertyOrder(11)]
    public HipLiveBadgeCertificateState? Certificate { get; }

    [JsonPropertyName("displayScore")]
    [JsonPropertyOrder(12)]
    public int? DisplayScore { get; }

    [JsonPropertyName("scorePresentation")]
    [JsonPropertyOrder(13)]
    public string ScorePresentation { get; }

    [JsonPropertyName("evidenceCoverage")]
    [JsonPropertyOrder(14)]
    public string EvidenceCoverage { get; }

    [JsonPropertyName("evidenceConfidence")]
    [JsonPropertyOrder(15)]
    public string EvidenceConfidence { get; }

    private static string RequiredPresentationValue(
        string value,
        string parameterName,
        params string[] allowedValues)
    {
        if (!allowedValues.Contains(value, StringComparer.Ordinal))
        {
            throw new ArgumentException("HIP live badge presentation value is unsupported.", parameterName);
        }

        return value;
    }

    private static string RequiredPublicText(string? value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > MaximumTextLength ||
            value.Any(char.IsControl))
        {
            throw new ArgumentException("HIP live badge public text is required and bounded.", parameterName);
        }

        return value;
    }

    private static DateTimeOffset RequiredUtcMillisecond(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero || value.Ticks % TimeSpan.TicksPerMillisecond != 0)
        {
            throw new ArgumentException("HIP live badge timestamps must be millisecond-precision UTC.", parameterName);
        }

        return value;
    }
}

/// <summary>A signed live badge. Its signature proves HIP origin and integrity, never safety by itself.</summary>
public sealed record HipLiveBadgeDocument(
    [property: JsonPropertyName("payload"), JsonPropertyOrder(0)] HipLiveBadgePayload Payload,
    [property: JsonPropertyName("issuer"), JsonPropertyOrder(1)] HipProtocolIssuer Issuer,
    [property: JsonPropertyName("signature"), JsonPropertyOrder(2)] HipProtocolSignature Signature)
{
    public const long MaximumDocumentBytes = 16_384;

    [JsonIgnore]
    public bool EstablishesSafetyOrReputationBySignatureAlone => false;
}

public enum HipLiveBadgeSignatureStatus
{
    Unspecified = 0,
    Verified,
    Malformed,
    Expired,
    TimestampOutsideTolerance,
    ValidityWindowExceeded,
    SignerUnavailable,
    SignerNotAuthorized,
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
    VerificationStateUnavailable
}

public sealed record HipLiveBadgeSigningResult(
    HipLiveBadgeSignatureStatus Status,
    HipLiveBadgeDocument? Document = null)
{
    public bool IsVerified => Status == HipLiveBadgeSignatureStatus.Verified && Document is not null;

    public bool EstablishesSafetyOrReputationBySignatureAlone => false;
}

public sealed record HipLiveBadgeVerificationResult(
    [property: JsonConverter(typeof(JsonStringEnumConverter<HipLiveBadgeSignatureStatus>))]
    HipLiveBadgeSignatureStatus Status)
{
    public bool IsVerified => Status == HipLiveBadgeSignatureStatus.Verified;

    public bool EstablishesSafetyOrReputationBySignatureAlone => false;
}

public interface IHipLiveBadgeSigningService
{
    Task<HipLiveBadgeSigningResult> SignAsync(
        HipLiveBadgeSigningRequest request,
        CancellationToken cancellationToken);
}

public interface IHipLiveBadgeVerificationService
{
    Task<HipLiveBadgeVerificationResult> VerifyAsync(
        HipLiveBadgeDocument document,
        CancellationToken cancellationToken);
}

/// <summary>Creates the exact JSON object hashed for live badge signing and verification.</summary>
public static class HipLiveBadgeSigningPayload
{
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();

    public static byte[] Create(HipLiveBadgeDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var json = JsonSerializer.SerializeToUtf8Bytes(document, SerializerOptions);
        using var parsed = JsonDocument.Parse(json);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var property in parsed.RootElement.EnumerateObject())
            {
                writer.WritePropertyName(property.Name);
                if (!string.Equals(property.Name, "signature", StringComparison.Ordinal))
                {
                    property.Value.WriteTo(writer);
                    continue;
                }

                writer.WriteStartObject();
                foreach (var signatureProperty in property.Value.EnumerateObject())
                {
                    if (!string.Equals(signatureProperty.Name, "value", StringComparison.Ordinal))
                    {
                        signatureProperty.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        return options;
    }
}
