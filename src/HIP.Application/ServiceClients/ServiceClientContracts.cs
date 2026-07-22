using System.Text;
using HIP.Application.PublicLookup;
using HIP.Domain.Audit;
using HIP.Domain.ServiceClients;

namespace HIP.Application.ServiceClients;

/// <summary>Defines the exact external scope strings accepted by HIP service-client boundaries.</summary>
public static class ServiceClientScopeValues
{
    public const string DomainVerificationCheck = "domain-verification:check";
    public const string SiteSafetyExternalEvidenceCheck = "site-safety:external-evidence:check";

    /// <summary>Parses a case-sensitive, non-wildcard scope value.</summary>
    public static ServiceClientScope ParseExact(string value) =>
        value switch
        {
            DomainVerificationCheck => ServiceClientScope.DomainVerificationCheck,
            SiteSafetyExternalEvidenceCheck => ServiceClientScope.SiteSafetyExternalEvidenceCheck,
            _ => throw new ArgumentException("The requested service-client scope is not supported.", nameof(value))
        };

    /// <summary>Returns the stable external value for a supported domain scope.</summary>
    public static string ToExternalValue(ServiceClientScope scope) =>
        scope switch
        {
            ServiceClientScope.DomainVerificationCheck => DomainVerificationCheck,
            ServiceClientScope.SiteSafetyExternalEvidenceCheck => SiteSafetyExternalEvidenceCheck,
            _ => throw new ArgumentOutOfRangeException(nameof(scope), "The service-client scope is not supported.")
        };
}

/// <summary>
/// Untrusted registration input. Actor and owner identifiers are intentionally absent and must be
/// derived from the privileged authenticated boundary.
/// </summary>
public sealed record CreateServiceClientRequest(
    string DisplayName,
    IReadOnlyCollection<string> Scopes,
    IReadOnlyCollection<string> DomainGrants,
    int? LifetimeDays = null);

/// <summary>Canonical registration facts safe to pass into the trusted lifecycle layer.</summary>
public sealed record ValidatedServiceClientRegistrationRequest(
    string DisplayName,
    ServiceClientScope Scope,
    IReadOnlyList<string> DomainGrants,
    int LifetimeDays);

/// <summary>Public-safe service-client projection that excludes owner scope and credential verifier.</summary>
public sealed record ServiceClientResponse(
    string ClientId,
    string DisplayName,
    string Scope,
    IReadOnlyList<string> DomainGrants,
    ServiceClientStatus Status,
    long CredentialVersion,
    long AggregateVersion,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset CredentialChangedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset? RevokedAtUtc);

/// <summary>
/// Holds raw service-client secret material only while it is generated, protected, verified, or
/// returned once. String formatting and ordinary JSON serialization do not reveal its value.
/// </summary>
public sealed class ServiceClientSecret
{
    private const int MaximumSecretLength = 1_024;
    private readonly string value;

    /// <summary>Creates a bounded in-memory sensitive value.</summary>
    public ServiceClientSecret(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > MaximumSecretLength ||
            value.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException("The service-client secret is not in a bounded canonical form.", nameof(value));
        }

        this.value = value;
    }

    /// <summary>
    /// Reveals the sensitive value only to an explicit protection, verification, or one-time response boundary.
    /// </summary>
    public string Reveal() => value;

    /// <inheritdoc />
    public override string ToString() => "[REDACTED]";
}

/// <summary>Returns the public registration plus the only application copy of its one-time raw secret.</summary>
public sealed record ServiceClientRegistrationResult(
    ServiceClientResponse Client,
    ServiceClientSecret OneTimeSecret);

/// <summary>Generates unpredictable opaque identifiers and high-entropy raw secrets.</summary>
public interface IServiceClientCredentialGenerator
{
    string GenerateClientId();

    ServiceClientSecret GenerateSecret();
}

/// <summary>Creates and verifies a deliberately slow protected representation of a raw secret.</summary>
public interface IServiceClientSecretProtector
{
    string Protect(string clientId, ServiceClientSecret secret);

    bool Verify(string clientId, ServiceClientSecret presentedSecret, string credentialVerifier);
}

/// <summary>Describes the result of an optimistic service-client persistence transition.</summary>
public enum ServiceClientSaveOutcome
{
    Succeeded = 0,
    VersionConflict = 1
}

/// <summary>
/// Commits one exact aggregate version together with the privacy-safe audit facts produced by that transition.
/// </summary>
public sealed class ServiceClientTransitionBatch
{
    /// <summary>Creates and validates one atomic service-client persistence batch.</summary>
    public ServiceClientTransitionBatch(
        ServiceClientRegistration registration,
        long expectedAggregateVersion,
        IReadOnlyCollection<AuditLogEntry> auditEntries)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(auditEntries);
        if (expectedAggregateVersion < 0 ||
            expectedAggregateVersion == long.MaxValue ||
            registration.AggregateVersion != expectedAggregateVersion + 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedAggregateVersion),
                "A service-client transition must advance the expected aggregate version by exactly one.");
        }

        var auditSnapshot = auditEntries.ToArray();
        if (auditSnapshot.Length is < 1 or > 8)
        {
            throw new ArgumentOutOfRangeException(
                nameof(auditEntries),
                "A service-client transition requires between one and eight audit facts.");
        }

        if (auditSnapshot.Any(entry =>
                entry is null ||
                entry.TargetType != HIP.Domain.Review.TargetType.ServiceClient ||
                !string.Equals(entry.TargetId, registration.ClientId, StringComparison.Ordinal) ||
                entry.CreatedAtUtc.Offset != TimeSpan.Zero ||
                ContainsCredentialMaterial(entry, registration.CredentialVerifier)))
        {
            throw new ArgumentException(
                "Service-client audit facts must use the exact client target, UTC time, and contain no credential material.",
                nameof(auditEntries));
        }

        if (auditSnapshot.Select(entry => entry.AuditLogId).Distinct(StringComparer.Ordinal).Count() != auditSnapshot.Length)
        {
            throw new ArgumentException("Service-client audit identifiers must be unique.", nameof(auditEntries));
        }

        Registration = registration;
        ExpectedAggregateVersion = expectedAggregateVersion;
        AuditEntries = Array.AsReadOnly(auditSnapshot);
    }

    public ServiceClientRegistration Registration { get; }

    public long ExpectedAggregateVersion { get; }

    public IReadOnlyCollection<AuditLogEntry> AuditEntries { get; }

    private static bool IsSensitiveAuditKey(string key) =>
        key.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("verifier", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("password", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsCredentialMaterial(AuditLogEntry entry, string credentialVerifier) =>
        ContainsVerifier(entry.AuditLogId, credentialVerifier) ||
        ContainsVerifier(entry.ActorId, credentialVerifier) ||
        ContainsVerifier(entry.Action, credentialVerifier) ||
        ContainsVerifier(entry.TargetId, credentialVerifier) ||
        ContainsVerifier(entry.Summary, credentialVerifier) ||
        ContainsVerifier(entry.CorrelationId, credentialVerifier) ||
        ContainsCredentialMaterial(entry.Metadata, credentialVerifier) ||
        ContainsCredentialMaterial(entry.BeforeMetadata, credentialVerifier) ||
        ContainsCredentialMaterial(entry.AfterMetadata, credentialVerifier);

    private static bool ContainsCredentialMaterial(
        IReadOnlyDictionary<string, string> metadata,
        string credentialVerifier) =>
        metadata.Any(pair =>
            IsSensitiveAuditKey(pair.Key) ||
            ContainsVerifier(pair.Key, credentialVerifier) ||
            ContainsVerifier(pair.Value, credentialVerifier));

    private static bool ContainsVerifier(string? candidate, string credentialVerifier) =>
        candidate?.Contains(credentialVerifier, StringComparison.Ordinal) == true;
}

/// <summary>Represents one bounded cursor page returned by owner-scoped repository listing.</summary>
public sealed class ServiceClientRepositoryPage
{
    public const int MaximumPageSize = 100;
    private const int MaximumCursorLength = 512;

    /// <summary>Creates a bounded page with an optional opaque continuation cursor.</summary>
    public ServiceClientRepositoryPage(
        IReadOnlyList<ServiceClientRegistration> items,
        string? nextCursor)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (items.Count > MaximumPageSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(items),
                $"A service-client repository page cannot exceed {MaximumPageSize} items.");
        }

        if (nextCursor is not null &&
            (string.IsNullOrWhiteSpace(nextCursor) || nextCursor.Length > MaximumCursorLength))
        {
            throw new ArgumentException("The service-client continuation cursor is invalid.", nameof(nextCursor));
        }

        Items = Array.AsReadOnly(items.ToArray());
        NextCursor = nextCursor;
    }

    /// <summary>Gets the bounded service-client snapshots in this page.</summary>
    public IReadOnlyList<ServiceClientRegistration> Items { get; }

    /// <summary>Gets the opaque continuation cursor, or null when this is the final page.</summary>
    public string? NextCursor { get; }
}

/// <summary>Persists versioned service-client snapshots using compare-and-swap semantics.</summary>
public interface IServiceClientRepository
{
    Task<ServiceClientRegistration?> GetAsync(string clientId, CancellationToken cancellationToken);

    Task<ServiceClientRepositoryPage> ListByOwnerAsync(
        string ownerScopeId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken);

    /// <summary>
    /// Lists one logical owner across the current owner partition and any explicitly configured
    /// legacy-key partitions. The first scope binds the opaque cursor and every scope is queried
    /// after the same decoded client ID before results are globally ordered.
    /// </summary>
    Task<ServiceClientRepositoryPage> ListByOwnerAsync(
        IReadOnlyList<string> ownerScopeIds,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken)
    {
        ServiceClientRepositoryCursor.ValidateOwnerScopeIds(ownerScopeIds);
        if (ownerScopeIds.Count != 1)
        {
            throw new NotSupportedException(
                "This service-client repository does not support legacy owner-partition listing.");
        }

        return ListByOwnerAsync(ownerScopeIds[0], cursor, pageSize, cancellationToken);
    }

    Task<ServiceClientSaveOutcome> TrySaveAsync(
        ServiceClientTransitionBatch transition,
        CancellationToken cancellationToken);
}

/// <summary>Validates and canonicalizes untrusted service-client registration input.</summary>
public static class ServiceClientRegistrationRequestValidator
{
    /// <summary>Returns canonical registration facts or throws for an invalid request.</summary>
    public static ValidatedServiceClientRegistrationRequest Validate(CreateServiceClientRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var displayName = NormalizeDisplayName(request.DisplayName);
        var scope = ValidateScope(request.Scopes);
        var domains = ValidateDomains(request.DomainGrants);
        var lifetimeDays = request.LifetimeDays ?? ServiceClientRegistrationLimits.DefaultLifetimeDays;
        if (lifetimeDays is < ServiceClientRegistrationLimits.MinimumLifetimeDays or
            > ServiceClientRegistrationLimits.MaximumLifetimeDays)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "Service-client lifetime must be between 1 and 365 days.");
        }

        return new ValidatedServiceClientRegistrationRequest(displayName, scope, domains, lifetimeDays);
    }

    private static string NormalizeDisplayName(string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        var normalized = displayName.Trim();
        if (Encoding.UTF8.GetByteCount(normalized) > ServiceClientRegistrationLimits.MaximumDisplayNameUtf8Bytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(displayName),
                $"Display name cannot exceed {ServiceClientRegistrationLimits.MaximumDisplayNameUtf8Bytes} UTF-8 bytes.");
        }

        if (normalized.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException("Display name cannot contain control or invalid Unicode characters.", nameof(displayName));
        }

        return normalized;
    }

    private static ServiceClientScope ValidateScope(IReadOnlyCollection<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        var snapshot = scopes.ToArray();
        if (snapshot.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("A service-client scope cannot be empty.", nameof(scopes));
        }

        if (snapshot.Distinct(StringComparer.Ordinal).Count() != snapshot.Length)
        {
            throw new ArgumentException("Duplicate service-client scopes are not allowed.", nameof(scopes));
        }

        if (snapshot.Length != 1)
        {
            throw new ArgumentException("A service client must request exactly one explicit scope.", nameof(scopes));
        }

        return ServiceClientScopeValues.ParseExact(snapshot[0]);
    }

    private static IReadOnlyList<string> ValidateDomains(IReadOnlyCollection<string> domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        if (domains.Count is < 1 or > ServiceClientRegistrationLimits.MaximumDomainGrants)
        {
            throw new ArgumentOutOfRangeException(
                nameof(domains),
                $"A service client requires between 1 and {ServiceClientRegistrationLimits.MaximumDomainGrants} domain grants.");
        }

        var normalized = domains
            .Select(DomainInputValidator.ValidateAndNormalize)
            .OrderBy(domain => domain, StringComparer.Ordinal)
            .ToArray();
        if (normalized.Distinct(StringComparer.Ordinal).Count() != normalized.Length)
        {
            throw new ArgumentException("Service-client domain grants must be unique after normalization.", nameof(domains));
        }

        return Array.AsReadOnly(normalized);
    }
}
