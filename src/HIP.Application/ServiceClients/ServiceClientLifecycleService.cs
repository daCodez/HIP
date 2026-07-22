using System.Globalization;
using System.Text;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Domain.ServiceClients;

namespace HIP.Application.ServiceClients;

/// <summary>Coordinates owner-bound service-client creation, listing, rotation, and revocation.</summary>
public sealed class ServiceClientLifecycleService(
    IServiceClientRepository repository,
    IServiceClientCredentialGenerator credentialGenerator,
    IServiceClientSecretProtector secretProtector,
    ServiceClientOwnerScopeDerivation ownerScopeDerivation,
    IAuditLogService auditLogService,
    TimeProvider timeProvider) : IServiceClientLifecycleService
{
    private const int MaximumIdentifierUtf8Bytes = 512;
    private const int MaximumClientIdCollisionRetries = 3;
    private const string AdministratorActorRole = "Administrator";
    private readonly IServiceClientRepository repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly IServiceClientCredentialGenerator credentialGenerator = credentialGenerator ?? throw new ArgumentNullException(nameof(credentialGenerator));
    private readonly IServiceClientSecretProtector secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    private readonly ServiceClientOwnerScopeDerivation ownerScopeDerivation = ownerScopeDerivation ?? throw new ArgumentNullException(nameof(ownerScopeDerivation));
    private readonly IAuditLogService auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
    private readonly TimeProvider timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<ServiceClientCreateResult> CreateAsync(
        string actorId, string ownerId, CreateServiceClientRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsValidTrustedIdentifier(actorId) || !TryDeriveOwnerScopes(ownerId, out var ownerScopeIds))
        {
            return CreateFailure(ServiceClientLifecycleOutcome.InvalidRequest);
        }

        var ownerScopeId = ownerScopeIds[0];

        ValidatedServiceClientRegistrationRequest validated;
        try
        {
            validated = ServiceClientRegistrationRequestValidator.Validate(request);
        }
        catch (ArgumentException)
        {
            return CreateFailure(ServiceClientLifecycleOutcome.InvalidRequest);
        }

        var now = timeProvider.GetUtcNow().ToUniversalTime();
        var expiresAtUtc = now.AddDays(validated.LifetimeDays);
        for (var attempt = 0; attempt <= MaximumClientIdCollisionRetries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var clientId = credentialGenerator.GenerateClientId();
            var secret = credentialGenerator.GenerateSecret();
            var verifier = secretProtector.Protect(clientId, secret);
            var registration = ServiceClientRegistration.Create(
                clientId, ownerScopeId, validated.DisplayName, validated.Scope, validated.DomainGrants,
                verifier, now, expiresAtUtc);
            var audit = CreateAudit(
                actorId, registration, ServiceClientAuditActions.Created,
                ServiceClientTransitionValidator.CreatedSummary, AuditSeverity.Medium, now,
                Metadata(registration,
                    ("credentialVersion", registration.CredentialVersion),
                    ("aggregateVersion", registration.AggregateVersion)));
            var outcome = await repository.TrySaveAsync(
                    new ServiceClientTransitionBatch(registration, 0, [audit]), cancellationToken)
                .ConfigureAwait(false);
            if (outcome == ServiceClientSaveOutcome.Succeeded)
            {
                ServiceClientTelemetry.RecordLifecycle(
                    ServiceClientLifecycleOperation.Create,
                    ServiceClientLifecycleOutcome.Succeeded,
                    validated.Scope);
                return new ServiceClientCreateResult(
                    ServiceClientLifecycleOutcome.Succeeded,
                    ServiceClientLifecycleMessages.Succeeded,
                    new ServiceClientRegistrationResult(ToResponse(registration), secret));
            }
        }

        return CreateFailure(ServiceClientLifecycleOutcome.Conflict);
    }

    public async Task<ServiceClientListResult> ListAsync(
        string ownerId, string? cursor, int pageSize, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryDeriveOwnerScopes(ownerId, out var ownerScopeIds) ||
            pageSize is < 1 or > ServiceClientRepositoryPage.MaximumPageSize)
        {
            return ListFailure(ServiceClientLifecycleOutcome.InvalidRequest);
        }

        try
        {
            var page = await repository.ListByOwnerAsync(ownerScopeIds, cursor, pageSize, cancellationToken)
                .ConfigureAwait(false);
            ServiceClientTelemetry.RecordLifecycle(
                ServiceClientLifecycleOperation.List,
                ServiceClientLifecycleOutcome.Succeeded);
            return new ServiceClientListResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                Array.AsReadOnly(page.Items.Select(ToResponse).ToArray()),
                page.NextCursor);
        }
        catch (ArgumentException)
        {
            return ListFailure(ServiceClientLifecycleOutcome.InvalidRequest);
        }
    }

    public async Task<ServiceClientRotationResult> RotateCredentialAsync(
        string actorId,
        string ownerId,
        string clientId,
        long expectedAggregateVersion,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsValidTrustedIdentifier(actorId) ||
            !TryDeriveOwnerScopes(ownerId, out var ownerScopeIds) ||
            !ServiceClientRepositoryCursor.IsCanonicalClientId(clientId) ||
            expectedAggregateVersion is < 1 or long.MaxValue)
        {
            return RotationFailure(ServiceClientLifecycleOutcome.InvalidRequest);
        }

        var current = await repository.GetAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (current is null || !OwnerMatches(current.OwnerScopeId, ownerScopeIds))
        {
            return RotationFailure(ServiceClientLifecycleOutcome.NotFound);
        }

        if (current.Status == ServiceClientStatus.Revoked)
        {
            return RotationFailure(ServiceClientLifecycleOutcome.Revoked);
        }

        var now = timeProvider.GetUtcNow().ToUniversalTime();
        if (current.IsExpired(now))
        {
            return RotationFailure(ServiceClientLifecycleOutcome.Expired);
        }

        if (current.AggregateVersion != expectedAggregateVersion)
        {
            return RotationFailure(ServiceClientLifecycleOutcome.Conflict);
        }

        var replacementSecret = credentialGenerator.GenerateSecret();
        var replacementVerifier = secretProtector.Protect(clientId, replacementSecret);
        var rotated = current.RotateCredential(replacementVerifier, now);
        var audit = CreateAudit(
            actorId, rotated, ServiceClientAuditActions.CredentialRotated,
            ServiceClientTransitionValidator.RotatedSummary, AuditSeverity.Medium, now,
            Metadata(rotated,
                ("previousCredentialVersion", current.CredentialVersion),
                ("credentialVersion", rotated.CredentialVersion),
                ("previousAggregateVersion", current.AggregateVersion),
                ("aggregateVersion", rotated.AggregateVersion)));
        var outcome = await repository.TrySaveAsync(
                new ServiceClientTransitionBatch(rotated, expectedAggregateVersion, [audit]),
                cancellationToken)
            .ConfigureAwait(false);
        if (outcome == ServiceClientSaveOutcome.Succeeded)
        {
            ServiceClientTelemetry.RecordLifecycle(
                ServiceClientLifecycleOperation.RotateCredential,
                ServiceClientLifecycleOutcome.Succeeded,
                rotated.Scope);
            return new ServiceClientRotationResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                new ServiceClientRegistrationResult(ToResponse(rotated), replacementSecret));
        }

        return RotationFailure(ServiceClientLifecycleOutcome.Conflict);
    }

    public async Task<ServiceClientRevocationResult> RevokeAsync(
        string actorId,
        string ownerId,
        string clientId,
        long expectedAggregateVersion,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsValidTrustedIdentifier(actorId) ||
            !TryDeriveOwnerScopes(ownerId, out var ownerScopeIds) ||
            !ServiceClientRepositoryCursor.IsCanonicalClientId(clientId) ||
            expectedAggregateVersion is < 1 or long.MaxValue)
        {
            return RevocationFailure(ServiceClientLifecycleOutcome.InvalidRequest);
        }

        var current = await repository.GetAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (current is null || !OwnerMatches(current.OwnerScopeId, ownerScopeIds))
        {
            return RevocationFailure(ServiceClientLifecycleOutcome.NotFound);
        }

        if (current.Status == ServiceClientStatus.Revoked)
        {
            return RevocationFailure(ServiceClientLifecycleOutcome.Revoked);
        }

        if (current.AggregateVersion != expectedAggregateVersion)
        {
            return RevocationFailure(ServiceClientLifecycleOutcome.Conflict);
        }

        var now = timeProvider.GetUtcNow().ToUniversalTime();
        var revoked = current.Revoke(now);
        var audit = CreateAudit(
            actorId, revoked, ServiceClientAuditActions.Revoked,
            ServiceClientTransitionValidator.RevokedSummary, AuditSeverity.High, now,
            Metadata(revoked,
                ("credentialVersion", revoked.CredentialVersion),
                ("previousAggregateVersion", current.AggregateVersion),
                ("aggregateVersion", revoked.AggregateVersion)));
        var outcome = await repository.TrySaveAsync(
                new ServiceClientTransitionBatch(revoked, expectedAggregateVersion, [audit]),
                cancellationToken)
            .ConfigureAwait(false);
        if (outcome == ServiceClientSaveOutcome.Succeeded)
        {
            ServiceClientTelemetry.RecordLifecycle(
                ServiceClientLifecycleOperation.Revoke,
                ServiceClientLifecycleOutcome.Succeeded,
                revoked.Scope);
            return new ServiceClientRevocationResult(
                ServiceClientLifecycleOutcome.Succeeded,
                ServiceClientLifecycleMessages.Succeeded,
                ToResponse(revoked));
        }

        return RevocationFailure(ServiceClientLifecycleOutcome.Conflict);
    }

    private bool TryDeriveOwnerScopes(string ownerId, out IReadOnlyList<string> ownerScopeIds)
    {
        ownerScopeIds = [];
        if (!IsValidTrustedIdentifier(ownerId))
        {
            return false;
        }

        ownerScopeIds = ownerScopeDerivation.OwnerScopeIds(ownerId);
        return true;
    }

    private static bool OwnerMatches(string storedOwnerScopeId, IReadOnlyList<string> candidateOwnerScopeIds) =>
        candidateOwnerScopeIds.Contains(storedOwnerScopeId, StringComparer.Ordinal);

    private static bool IsValidTrustedIdentifier(string value) =>
        !string.IsNullOrWhiteSpace(value) &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        Encoding.UTF8.GetByteCount(value) <= MaximumIdentifierUtf8Bytes &&
        !value.Any(character => char.IsControl(character) || char.IsSurrogate(character));

    private AuditLogEntry CreateAudit(
        string actorId,
        ServiceClientRegistration registration,
        string action,
        string summary,
        AuditSeverity severity,
        DateTimeOffset createdAtUtc,
        IReadOnlyDictionary<string, string> metadata) =>
        AuditLogIntegrity.Seal(auditLogService.CreateEntry(
            actorId, action, TargetType.ServiceClient, registration.ClientId, summary, severity,
            metadata, actorRole: AdministratorActorRole) with
        {
            CreatedAtUtc = createdAtUtc
        });

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

    private static ServiceClientResponse ToResponse(ServiceClientRegistration registration) =>
        new(
            registration.ClientId,
            registration.DisplayName,
            ServiceClientScopeValues.ToExternalValue(registration.Scope),
            Array.AsReadOnly(registration.DomainGrants.ToArray()),
            registration.Status,
            registration.CredentialVersion,
            registration.AggregateVersion,
            registration.CreatedAtUtc,
            registration.CredentialChangedAtUtc,
            registration.ExpiresAtUtc,
            registration.RevokedAtUtc);

    private static ServiceClientCreateResult CreateFailure(ServiceClientLifecycleOutcome outcome)
    {
        ServiceClientTelemetry.RecordLifecycle(ServiceClientLifecycleOperation.Create, outcome);
        return new(outcome, Message(outcome));
    }

    private static ServiceClientListResult ListFailure(ServiceClientLifecycleOutcome outcome)
    {
        ServiceClientTelemetry.RecordLifecycle(ServiceClientLifecycleOperation.List, outcome);
        return new(outcome, Message(outcome), []);
    }

    private static ServiceClientRotationResult RotationFailure(ServiceClientLifecycleOutcome outcome)
    {
        ServiceClientTelemetry.RecordLifecycle(ServiceClientLifecycleOperation.RotateCredential, outcome);
        return new(outcome, Message(outcome));
    }

    private static ServiceClientRevocationResult RevocationFailure(ServiceClientLifecycleOutcome outcome)
    {
        ServiceClientTelemetry.RecordLifecycle(ServiceClientLifecycleOperation.Revoke, outcome);
        return new(outcome, Message(outcome));
    }

    private static string Message(ServiceClientLifecycleOutcome outcome) => outcome switch
    {
        ServiceClientLifecycleOutcome.Succeeded => ServiceClientLifecycleMessages.Succeeded,
        ServiceClientLifecycleOutcome.InvalidRequest => ServiceClientLifecycleMessages.InvalidRequest,
        ServiceClientLifecycleOutcome.NotFound => ServiceClientLifecycleMessages.ResourceUnavailable,
        ServiceClientLifecycleOutcome.Conflict => ServiceClientLifecycleMessages.Conflict,
        ServiceClientLifecycleOutcome.Expired => ServiceClientLifecycleMessages.Expired,
        ServiceClientLifecycleOutcome.Revoked => ServiceClientLifecycleMessages.Revoked,
        _ => ServiceClientLifecycleMessages.Unavailable
    };
}
