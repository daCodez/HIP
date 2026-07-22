using System.Globalization;
using HIP.Domain.Audit;
using HIP.Domain.ServiceClients;

namespace HIP.Application.ServiceClients;

/// <summary>Enforces the same service-client aggregate and audit invariants for every repository.</summary>
public static class ServiceClientTransitionValidator
{
    internal const string CreatedSummary = "A service client was registered.";
    internal const string RotatedSummary = "A service-client credential was replaced.";
    internal const string RevokedSummary = "A service client was irreversibly revoked.";
    private const int MaximumActorIdUtf8Bytes = 512;

    public static void ValidateTransition(ServiceClientTransitionBatch transition)
    {
        ArgumentNullException.ThrowIfNull(transition);
        if (transition.AuditEntries.Count != 1)
        {
            throw new ArgumentException("A service-client transition requires exactly one audit fact.", nameof(transition));
        }

        var audit = transition.AuditEntries.Single();
        if (string.IsNullOrWhiteSpace(audit.ActorId) ||
            !string.Equals(audit.ActorId, audit.ActorId.Trim(), StringComparison.Ordinal) ||
            System.Text.Encoding.UTF8.GetByteCount(audit.ActorId) > MaximumActorIdUtf8Bytes ||
            audit.ActorId.Any(character => char.IsControl(character) || char.IsSurrogate(character)) ||
            !string.Equals(audit.ActorRole, "Administrator", StringComparison.Ordinal) ||
            audit.BeforeMetadata.Count != 0 ||
            audit.AfterMetadata.Count != 0 ||
            audit.CorrelationId is not null)
        {
            throw new ArgumentException("The service-client audit actor or metadata shape is invalid.", nameof(transition));
        }
    }

    public static void ValidateDelta(
        ServiceClientRegistration? previous,
        ServiceClientTransitionBatch transition)
    {
        ValidateTransition(transition);
        var current = transition.Registration;
        if (transition.ExpectedAggregateVersion == 0)
        {
            if (previous is not null ||
                current.AggregateVersion != 1 ||
                current.CredentialVersion != 1 ||
                current.Status != ServiceClientStatus.Active)
            {
                throw new ArgumentException("The initial service-client transition is invalid.", nameof(transition));
            }

            ValidateAudit(
                transition.AuditEntries.Single(),
                ServiceClientAuditActions.Created,
                CreatedSummary,
                AuditSeverity.Medium,
                current.CreatedAtUtc,
                Metadata(
                    current,
                    ("credentialVersion", current.CredentialVersion),
                    ("aggregateVersion", current.AggregateVersion)));
            return;
        }

        if (previous is null || previous.AggregateVersion != transition.ExpectedAggregateVersion)
        {
            throw new ArgumentException("The prior service-client aggregate does not match the expected version.", nameof(transition));
        }

        ValidateImmutableFacts(previous, current);
        if (previous.Status == ServiceClientStatus.Revoked)
        {
            throw new InvalidOperationException("A revoked service client cannot transition.");
        }

        if (IsCredentialRotation(previous, current))
        {
            ValidateAudit(
                transition.AuditEntries.Single(),
                ServiceClientAuditActions.CredentialRotated,
                RotatedSummary,
                AuditSeverity.Medium,
                current.CredentialChangedAtUtc,
                Metadata(
                    current,
                    ("previousCredentialVersion", previous.CredentialVersion),
                    ("credentialVersion", current.CredentialVersion),
                    ("previousAggregateVersion", previous.AggregateVersion),
                    ("aggregateVersion", current.AggregateVersion)));
            return;
        }

        if (IsRevocation(previous, current))
        {
            ValidateAudit(
                transition.AuditEntries.Single(),
                ServiceClientAuditActions.Revoked,
                RevokedSummary,
                AuditSeverity.High,
                current.RevokedAtUtc!.Value,
                Metadata(
                    current,
                    ("credentialVersion", current.CredentialVersion),
                    ("previousAggregateVersion", previous.AggregateVersion),
                    ("aggregateVersion", current.AggregateVersion)));
            return;
        }

        throw new ArgumentException("The service-client lifecycle transition is not allowed.", nameof(transition));
    }

    private static void ValidateImmutableFacts(
        ServiceClientRegistration previous,
        ServiceClientRegistration current)
    {
        if (!string.Equals(previous.ClientId, current.ClientId, StringComparison.Ordinal) ||
            !string.Equals(previous.OwnerScopeId, current.OwnerScopeId, StringComparison.Ordinal) ||
            !string.Equals(previous.DisplayName, current.DisplayName, StringComparison.Ordinal) ||
            previous.Scope != current.Scope ||
            !previous.DomainGrants.SequenceEqual(current.DomainGrants, StringComparer.Ordinal) ||
            previous.CreatedAtUtc != current.CreatedAtUtc ||
            previous.ExpiresAtUtc != current.ExpiresAtUtc ||
            current.AggregateVersion != previous.AggregateVersion + 1)
        {
            throw new ArgumentException("Immutable service-client registration facts changed.", nameof(current));
        }
    }

    private static bool IsCredentialRotation(
        ServiceClientRegistration previous,
        ServiceClientRegistration current) =>
        previous.Status == ServiceClientStatus.Active &&
        current.Status == ServiceClientStatus.Active &&
        current.CredentialVersion == previous.CredentialVersion + 1 &&
        !string.Equals(current.CredentialVerifier, previous.CredentialVerifier, StringComparison.Ordinal) &&
        current.CredentialChangedAtUtc >= previous.CredentialChangedAtUtc &&
        current.StatusChangedAtUtc == previous.StatusChangedAtUtc &&
        current.RevokedAtUtc is null &&
        previous.RevokedAtUtc is null;

    private static bool IsRevocation(
        ServiceClientRegistration previous,
        ServiceClientRegistration current) =>
        previous.Status == ServiceClientStatus.Active &&
        current.Status == ServiceClientStatus.Revoked &&
        current.CredentialVersion == previous.CredentialVersion &&
        string.Equals(current.CredentialVerifier, previous.CredentialVerifier, StringComparison.Ordinal) &&
        current.CredentialChangedAtUtc == previous.CredentialChangedAtUtc &&
        current.StatusChangedAtUtc == current.RevokedAtUtc &&
        current.StatusChangedAtUtc >= previous.StatusChangedAtUtc &&
        current.StatusChangedAtUtc >= previous.CredentialChangedAtUtc;

    private static IReadOnlyDictionary<string, string> Metadata(
        ServiceClientRegistration registration,
        params (string Key, long Value)[] versions)
    {
        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scope"] = ServiceClientScopeValues.ToExternalValue(registration.Scope),
            ["domainGrantCount"] = registration.DomainGrants.Count.ToString(CultureInfo.InvariantCulture)
        };
        foreach (var (key, value) in versions)
        {
            metadata[key] = value.ToString(CultureInfo.InvariantCulture);
        }

        return metadata;
    }

    private static void ValidateAudit(
        AuditLogEntry audit,
        string action,
        string summary,
        AuditSeverity severity,
        DateTimeOffset createdAtUtc,
        IReadOnlyDictionary<string, string> expectedMetadata)
    {
        if (!string.Equals(audit.Action, action, StringComparison.Ordinal) ||
            !string.Equals(audit.Summary, summary, StringComparison.Ordinal) ||
            audit.Severity != severity ||
            audit.CreatedAtUtc != createdAtUtc ||
            audit.Metadata.Count != expectedMetadata.Count ||
            expectedMetadata.Any(pair =>
                !audit.Metadata.TryGetValue(pair.Key, out var value) ||
                !string.Equals(value, pair.Value, StringComparison.Ordinal)))
        {
            throw new ArgumentException("The service-client audit fact does not match its lifecycle transition.", nameof(audit));
        }
    }
}
