using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace HIP.Domain.ServiceClients;

/// <summary>Identifies the one least-privilege operation authorized for a service client.</summary>
public enum ServiceClientScope
{
    DomainVerificationCheck = 0,
    SiteSafetyExternalEvidenceCheck = 1
}

/// <summary>Tracks the terminal lifecycle state of a service client.</summary>
public enum ServiceClientStatus
{
    Active = 0,
    Revoked = 1
}

/// <summary>Defines stable size and lifetime bounds shared by service-client boundaries.</summary>
public static class ServiceClientRegistrationLimits
{
    public const int MaximumDisplayNameUtf8Bytes = 128;
    public const int MaximumDomainGrants = 16;
    public const int MinimumLifetimeDays = 1;
    public const int DefaultLifetimeDays = 90;
    public const int MaximumLifetimeDays = 365;
}

/// <summary>
/// Represents one owner-bound service client. It retains only a protected credential verifier;
/// raw client secrets are deliberately absent from the domain model.
/// </summary>
public sealed class ServiceClientRegistration
{
    private const string ClientIdPrefix = "hipc_v1_";
    private const int ClientIdRandomPartLength = 22;
    private const string OwnerScopeIdPrefix = "service-client-owner-hmac-sha256-v1:";
    private const int OwnerScopeIdDigestLength = 64;
    private const int MinimumCredentialVerifierLength = 32;
    private const int MaximumCredentialVerifierLength = 4_096;
    private readonly ReadOnlyCollection<string> domainGrants;

    [JsonConstructor]
    private ServiceClientRegistration(
        string clientId,
        string ownerScopeId,
        string displayName,
        ServiceClientScope scope,
        IReadOnlyList<string> domainGrants,
        ServiceClientStatus status,
        string credentialVerifier,
        long credentialVersion,
        long aggregateVersion,
        DateTimeOffset createdAtUtc,
        DateTimeOffset credentialChangedAtUtc,
        DateTimeOffset statusChangedAtUtc,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset? revokedAtUtc)
    {
        ClientId = ServiceClientRegistrationValidation.ValidateClientId(clientId, nameof(clientId));
        OwnerScopeId = ServiceClientRegistrationValidation.ValidateOwnerScopeId(
            ownerScopeId,
            nameof(ownerScopeId));
        DisplayName = ServiceClientRegistrationValidation.NormalizeDisplayName(displayName, nameof(displayName));

        if (!Enum.IsDefined(scope))
        {
            throw new ArgumentOutOfRangeException(nameof(scope), "The service-client scope is not supported.");
        }

        Scope = scope;
        this.domainGrants = Array.AsReadOnly(
            ServiceClientRegistrationValidation.ValidateDomainGrants(domainGrants, nameof(domainGrants)));
        Status = status;
        CredentialVerifier = ServiceClientRegistrationValidation.ValidateCredentialVerifier(
            credentialVerifier,
            MinimumCredentialVerifierLength,
            MaximumCredentialVerifierLength,
            nameof(credentialVerifier));
        ValidateLifecycle(
            status,
            credentialVersion,
            aggregateVersion,
            createdAtUtc,
            credentialChangedAtUtc,
            statusChangedAtUtc,
            expiresAtUtc,
            revokedAtUtc);

        CredentialVersion = credentialVersion;
        AggregateVersion = aggregateVersion;
        CreatedAtUtc = createdAtUtc;
        CredentialChangedAtUtc = credentialChangedAtUtc;
        StatusChangedAtUtc = statusChangedAtUtc;
        ExpiresAtUtc = expiresAtUtc;
        RevokedAtUtc = revokedAtUtc;
    }

    /// <summary>Gets the fixed-format, opaque and case-sensitive client identifier.</summary>
    public string ClientId { get; }

    /// <summary>Gets the privacy-scoped owner identifier derived by the trusted application boundary.</summary>
    public string OwnerScopeId { get; }

    /// <summary>Gets the operator-facing, bounded display name.</summary>
    public string DisplayName { get; }

    /// <summary>Gets the single operation authorized for this client.</summary>
    public ServiceClientScope Scope { get; }

    /// <summary>Gets the canonical public domains this client may access by exact match.</summary>
    public IReadOnlyList<string> DomainGrants => domainGrants;

    /// <summary>Gets the terminal client lifecycle state.</summary>
    public ServiceClientStatus Status { get; }

    /// <summary>
    /// Gets the slow, verifiable protected credential representation. This is not a raw secret and
    /// must never be projected into an API response or audit record.
    /// </summary>
    public string CredentialVerifier { get; }

    /// <summary>Gets the monotonic version of the credential verifier.</summary>
    public long CredentialVersion { get; }

    /// <summary>Gets the monotonic aggregate version used for optimistic concurrency.</summary>
    public long AggregateVersion { get; }

    /// <summary>Gets when the service client was created.</summary>
    public DateTimeOffset CreatedAtUtc { get; }

    /// <summary>Gets when the current credential version was installed.</summary>
    public DateTimeOffset CredentialChangedAtUtc { get; }

    /// <summary>Gets when the current terminal lifecycle state began.</summary>
    public DateTimeOffset StatusChangedAtUtc { get; }

    /// <summary>Gets the exclusive credential-expiration boundary.</summary>
    public DateTimeOffset ExpiresAtUtc { get; }

    /// <summary>Gets when terminal revocation occurred, when applicable.</summary>
    public DateTimeOffset? RevokedAtUtc { get; }

    /// <summary>Creates the initial active, version-one service-client aggregate.</summary>
    public static ServiceClientRegistration Create(
        string clientId,
        string ownerScopeId,
        string displayName,
        ServiceClientScope scope,
        IReadOnlyList<string> domainGrants,
        string credentialVerifier,
        DateTimeOffset createdAtUtc,
        DateTimeOffset expiresAtUtc) =>
        new(
            clientId,
            ownerScopeId,
            displayName,
            scope,
            domainGrants,
            ServiceClientStatus.Active,
            credentialVerifier,
            credentialVersion: 1,
            aggregateVersion: 1,
            createdAtUtc,
            credentialChangedAtUtc: createdAtUtc,
            statusChangedAtUtc: createdAtUtc,
            expiresAtUtc,
            revokedAtUtc: null);

    /// <summary>Replaces the protected verifier and advances both credential and aggregate versions.</summary>
    public ServiceClientRegistration RotateCredential(
        string replacementCredentialVerifier,
        DateTimeOffset transitionAtUtc)
    {
        EnsureActive("rotate its credential");
        EnsureOrderedUtc(transitionAtUtc, nameof(transitionAtUtc));
        if (transitionAtUtc >= ExpiresAtUtc)
        {
            throw new InvalidOperationException(
                $"Service client '{ClientId}' cannot rotate an expired credential.");
        }
        if (string.Equals(CredentialVerifier, replacementCredentialVerifier, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Service client '{ClientId}' credential rotation must install new protected material.");
        }

        return new ServiceClientRegistration(
            ClientId,
            OwnerScopeId,
            DisplayName,
            Scope,
            domainGrants,
            Status,
            replacementCredentialVerifier,
            NextVersion(CredentialVersion, "credential"),
            NextVersion(AggregateVersion, "aggregate"),
            CreatedAtUtc,
            transitionAtUtc,
            StatusChangedAtUtc,
            ExpiresAtUtc,
            RevokedAtUtc);
    }

    /// <summary>Irreversibly revokes this service client while retaining its credential history version.</summary>
    public ServiceClientRegistration Revoke(DateTimeOffset transitionAtUtc)
    {
        EnsureActive("revoke it");
        EnsureOrderedUtc(transitionAtUtc, nameof(transitionAtUtc));

        return new ServiceClientRegistration(
            ClientId,
            OwnerScopeId,
            DisplayName,
            Scope,
            domainGrants,
            ServiceClientStatus.Revoked,
            CredentialVerifier,
            CredentialVersion,
            NextVersion(AggregateVersion, "aggregate"),
            CreatedAtUtc,
            CredentialChangedAtUtc,
            transitionAtUtc,
            ExpiresAtUtc,
            transitionAtUtc);
    }

    /// <summary>Returns true only for an ordinal, already-normalized domain grant.</summary>
    public bool HasExactDomainGrant(string normalizedDomain) =>
        normalizedDomain is not null && domainGrants.Contains(normalizedDomain, StringComparer.Ordinal);

    /// <summary>Returns true at and after the exclusive server-owned expiry boundary.</summary>
    public bool IsExpired(DateTimeOffset atUtc)
    {
        ServiceClientRegistrationValidation.EnsureUtc(atUtc, nameof(atUtc));
        return atUtc >= ExpiresAtUtc;
    }

    private static void ValidateLifecycle(
        ServiceClientStatus status,
        long credentialVersion,
        long aggregateVersion,
        DateTimeOffset createdAtUtc,
        DateTimeOffset credentialChangedAtUtc,
        DateTimeOffset statusChangedAtUtc,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset? revokedAtUtc)
    {
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), "The service-client status is not supported.");
        }

        if (credentialVersion < 1 || aggregateVersion < credentialVersion)
        {
            throw new ArgumentOutOfRangeException(
                nameof(aggregateVersion),
                "Credential and aggregate versions must be positive and monotonically ordered.");
        }

        ServiceClientRegistrationValidation.EnsureUtc(createdAtUtc, nameof(createdAtUtc));
        ServiceClientRegistrationValidation.EnsureUtc(credentialChangedAtUtc, nameof(credentialChangedAtUtc));
        ServiceClientRegistrationValidation.EnsureUtc(statusChangedAtUtc, nameof(statusChangedAtUtc));
        ServiceClientRegistrationValidation.EnsureUtc(expiresAtUtc, nameof(expiresAtUtc));
        ServiceClientRegistrationValidation.EnsureOptionalUtc(revokedAtUtc, nameof(revokedAtUtc));

        var credentialLifetime = expiresAtUtc - createdAtUtc;
        if (credentialLifetime < TimeSpan.FromDays(ServiceClientRegistrationLimits.MinimumLifetimeDays) ||
            credentialLifetime > TimeSpan.FromDays(ServiceClientRegistrationLimits.MaximumLifetimeDays))
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAtUtc),
                "Service-client credentials must expire between 1 and 365 days after registration.");
        }

        if (credentialChangedAtUtc < createdAtUtc ||
            credentialChangedAtUtc >= expiresAtUtc ||
            statusChangedAtUtc < createdAtUtc)
        {
            throw new ArgumentException("Service-client lifecycle timestamps are not chronologically valid.");
        }

        var stateIsValid = status switch
        {
            ServiceClientStatus.Active => revokedAtUtc is null && statusChangedAtUtc == createdAtUtc,
            ServiceClientStatus.Revoked =>
                revokedAtUtc == statusChangedAtUtc && statusChangedAtUtc >= credentialChangedAtUtc,
            _ => false
        };
        if (!stateIsValid)
        {
            throw new ArgumentException("Service-client lifecycle state is inconsistent.");
        }
    }

    private void EnsureActive(string operation)
    {
        if (Status != ServiceClientStatus.Active)
        {
            throw new InvalidOperationException(
                $"Service client '{ClientId}' is revoked and cannot {operation}.");
        }
    }

    private void EnsureOrderedUtc(DateTimeOffset transitionAtUtc, string parameterName)
    {
        ServiceClientRegistrationValidation.EnsureUtc(transitionAtUtc, parameterName);
        if (transitionAtUtc < CredentialChangedAtUtc || transitionAtUtc < StatusChangedAtUtc)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                transitionAtUtc,
                "A service-client transition cannot precede current state.");
        }
    }

    private long NextVersion(long current, string versionName)
    {
        try
        {
            return checked(current + 1);
        }
        catch (OverflowException exception)
        {
            throw new InvalidOperationException(
                $"Service client '{ClientId}' exhausted its {versionName} version.",
                exception);
        }
    }

    private static class ServiceClientRegistrationValidation
    {
        private static readonly Regex CanonicalDomainPattern = new(
            @"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);

        public static string ValidateClientId(string value, string parameterName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
            if (value.Length != ClientIdPrefix.Length + ClientIdRandomPartLength ||
                !value.StartsWith(ClientIdPrefix, StringComparison.Ordinal) ||
                value.AsSpan(ClientIdPrefix.Length).ContainsAnyExcept(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") ||
                value[^1] is not ('A' or 'Q' or 'g' or 'w'))
            {
                throw new ArgumentException(
                    "Service-client identifiers must use canonical hipc_v1_ plus 22-character base64url form.",
                    parameterName);
            }

            return value;
        }

        public static string ValidateOwnerScopeId(string value, string parameterName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
            if (value.Length != OwnerScopeIdPrefix.Length + OwnerScopeIdDigestLength ||
                !value.StartsWith(OwnerScopeIdPrefix, StringComparison.Ordinal) ||
                value.AsSpan(OwnerScopeIdPrefix.Length).ContainsAnyExcept("0123456789abcdef"))
            {
                throw new ArgumentException(
                    "Service-client owner scope identifiers must use the exact versioned HMAC-SHA-256 form.",
                    parameterName);
            }

            return value;
        }

        public static string NormalizeDisplayName(string value, string parameterName)
        {
            var normalized = NormalizeBounded(
                value,
                ServiceClientRegistrationLimits.MaximumDisplayNameUtf8Bytes,
                parameterName,
                "Display name",
                measureUtf8Bytes: true);
            if (normalized.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
            {
                throw new ArgumentException("Display names cannot contain control or invalid Unicode characters.", parameterName);
            }

            return normalized;
        }

        public static string[] ValidateDomainGrants(
            IReadOnlyList<string> values,
            string parameterName)
        {
            ArgumentNullException.ThrowIfNull(values, parameterName);
            if (values.Count is < 1 or > ServiceClientRegistrationLimits.MaximumDomainGrants)
            {
                throw new ArgumentOutOfRangeException(
                    parameterName,
                    $"A service client requires between 1 and {ServiceClientRegistrationLimits.MaximumDomainGrants} domain grants.");
            }

            var snapshot = values.ToArray();
            if (snapshot.Any(value =>
                    string.IsNullOrWhiteSpace(value) ||
                    value != value.Trim() ||
                    value != value.ToLowerInvariant() ||
                    Uri.CheckHostName(value) != UriHostNameType.Dns ||
                    !CanonicalDomainPattern.IsMatch(value)))
            {
                throw new ArgumentException("Service-client domain grants must be canonical public domain names.", parameterName);
            }

            Array.Sort(snapshot, StringComparer.Ordinal);
            if (snapshot.Distinct(StringComparer.Ordinal).Count() != snapshot.Length)
            {
                throw new ArgumentException("Service-client domain grants must be unique.", parameterName);
            }

            return snapshot;
        }

        public static string ValidateCredentialVerifier(
            string value,
            int minimumLength,
            int maximumLength,
            string parameterName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
            if (value != value.Trim() ||
                value.Length < minimumLength ||
                value.Length > maximumLength ||
                value.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
            {
                throw new ArgumentException("The protected credential verifier is not in a bounded canonical form.", parameterName);
            }

            return value;
        }

        public static string NormalizeBounded(
            string value,
            int maximumLength,
            string parameterName,
            string displayName,
            bool measureUtf8Bytes = false)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
            var normalized = value.Trim();
            var length = measureUtf8Bytes ? Encoding.UTF8.GetByteCount(normalized) : normalized.Length;
            if (length > maximumLength)
            {
                throw new ArgumentOutOfRangeException(
                    parameterName,
                    $"{displayName} cannot exceed {maximumLength} {(measureUtf8Bytes ? "UTF-8 bytes" : "characters")}.");
            }

            return normalized;
        }

        public static void EnsureUtc(DateTimeOffset value, string parameterName)
        {
            if (value.Offset != TimeSpan.Zero)
            {
                throw new ArgumentException("Service-client timestamps must use the UTC offset.", parameterName);
            }
        }

        public static void EnsureOptionalUtc(DateTimeOffset? value, string parameterName)
        {
            if (value is not null)
            {
                EnsureUtc(value.Value, parameterName);
            }
        }
    }
}
