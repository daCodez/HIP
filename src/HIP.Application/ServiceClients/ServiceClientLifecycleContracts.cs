using HIP.Domain.ServiceClients;

namespace HIP.Application.ServiceClients;

/// <summary>Stable, non-sensitive outcomes returned by service-client management operations.</summary>
public enum ServiceClientLifecycleOutcome
{
    Succeeded = 0,
    InvalidRequest = 1,
    NotFound = 2,
    Conflict = 3,
    Expired = 4,
    Revoked = 5,
    Unavailable = 6,
    Throttled = 7
}

/// <summary>Stable management messages that do not reveal owner, credential, or existence details.</summary>
public static class ServiceClientLifecycleMessages
{
    public const string Succeeded = "The service-client operation succeeded.";
    public const string InvalidRequest = "The service-client request is invalid.";
    public const string ResourceUnavailable = "The service client is unavailable.";
    public const string Conflict = "The service client changed. Refresh and try again.";
    public const string Expired = "The service-client credential has expired.";
    public const string Revoked = "The service client is revoked.";
    public const string Unavailable = "The service-client service is unavailable.";
    public const string Throttled = "Too many service-client changes. Try again later.";
}

/// <summary>Exact audit action identifiers accepted by the persistence transition validator.</summary>
public static class ServiceClientAuditActions
{
    public const string Created = "ServiceClient.Created";
    public const string CredentialRotated = "ServiceClient.CredentialRotated";
    public const string Revoked = "ServiceClient.Revoked";
}

/// <summary>Result of creating a service client.</summary>
public sealed record ServiceClientCreateResult(
    ServiceClientLifecycleOutcome Outcome,
    string Message,
    ServiceClientRegistrationResult? Registration = null);

/// <summary>Bounded, owner-scoped management page.</summary>
public sealed record ServiceClientListResult(
    ServiceClientLifecycleOutcome Outcome,
    string Message,
    IReadOnlyList<ServiceClientResponse> Items,
    string? NextCursor = null);

/// <summary>Result of replacing service-client credential material.</summary>
public sealed record ServiceClientRotationResult(
    ServiceClientLifecycleOutcome Outcome,
    string Message,
    ServiceClientRegistrationResult? Registration = null);

/// <summary>Result of terminally revoking a service client.</summary>
public sealed record ServiceClientRevocationResult(
    ServiceClientLifecycleOutcome Outcome,
    string Message,
    ServiceClientResponse? Client = null);

/// <summary>
/// Performs owner-bound service-client lifecycle transitions. Actor and owner identifiers are
/// trusted boundary inputs and are deliberately separate from untrusted request bodies.
/// </summary>
public interface IServiceClientLifecycleService
{
    Task<ServiceClientCreateResult> CreateAsync(
        string actorId,
        string ownerId,
        CreateServiceClientRequest request,
        CancellationToken cancellationToken);

    Task<ServiceClientListResult> ListAsync(
        string ownerId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken);

    Task<ServiceClientRotationResult> RotateCredentialAsync(
        string actorId,
        string ownerId,
        string clientId,
        long expectedAggregateVersion,
        CancellationToken cancellationToken);

    Task<ServiceClientRevocationResult> RevokeAsync(
        string actorId,
        string ownerId,
        string clientId,
        long expectedAggregateVersion,
        CancellationToken cancellationToken);
}
