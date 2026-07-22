using System.Diagnostics;
using System.Diagnostics.Metrics;
using HIP.Domain.ServiceClients;

namespace HIP.Application.ServiceClients;

/// <summary>Bounded lifecycle operation names used by HIP service-client metrics.</summary>
public enum ServiceClientLifecycleOperation
{
    Create = 0,
    List = 1,
    RotateCredential = 2,
    Revoke = 3
}

/// <summary>Bounded authentication outcomes that never contain credential or resource identifiers.</summary>
public enum ServiceClientAuthenticationOutcome
{
    Succeeded = 0,
    InvalidCredential = 1,
    Throttled = 2,
    Unavailable = 3
}

/// <summary>
/// Emits low-cardinality service-client counters without client IDs, owners, domains, sources, or credential material.
/// </summary>
public static class ServiceClientTelemetry
{
    public const string MeterName = "HIP.ServiceClients";
    public const string LifecycleCounterName = "hip.service_client.lifecycle.operations";
    public const string AuthenticationCounterName = "hip.service_client.authentication.attempts";

    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> LifecycleCounter = Meter.CreateCounter<long>(
        LifecycleCounterName,
        unit: "{operation}",
        description: "Service-client management operations by bounded operation, outcome, and scope.");
    private static readonly Counter<long> AuthenticationCounter = Meter.CreateCounter<long>(
        AuthenticationCounterName,
        unit: "{attempt}",
        description: "Service-client authentication attempts by bounded outcome and scope.");

    /// <summary>Records one lifecycle result using enum-derived, low-cardinality tags only.</summary>
    public static void RecordLifecycle(
        ServiceClientLifecycleOperation operation,
        ServiceClientLifecycleOutcome outcome,
        ServiceClientScope? scope = null)
    {
        TagList tags = default;
        tags.Add("operation", LifecycleOperationValue(operation));
        tags.Add("outcome", LifecycleOutcomeValue(outcome));
        tags.Add("scope", ScopeValue(scope));
        LifecycleCounter.Add(1, tags);
    }

    /// <summary>Records one authentication result using enum-derived, low-cardinality tags only.</summary>
    public static void RecordAuthentication(
        ServiceClientAuthenticationOutcome outcome,
        ServiceClientScope? scope = null)
    {
        TagList tags = default;
        tags.Add("outcome", AuthenticationOutcomeValue(outcome));
        tags.Add("scope", ScopeValue(scope));
        AuthenticationCounter.Add(1, tags);
    }

    private static string LifecycleOperationValue(ServiceClientLifecycleOperation operation) => operation switch
    {
        ServiceClientLifecycleOperation.Create => "create",
        ServiceClientLifecycleOperation.List => "list",
        ServiceClientLifecycleOperation.RotateCredential => "rotate-credential",
        ServiceClientLifecycleOperation.Revoke => "revoke",
        _ => throw new ArgumentOutOfRangeException(nameof(operation), "Unsupported service-client lifecycle operation.")
    };

    private static string LifecycleOutcomeValue(ServiceClientLifecycleOutcome outcome) => outcome switch
    {
        ServiceClientLifecycleOutcome.Succeeded => "succeeded",
        ServiceClientLifecycleOutcome.InvalidRequest => "invalid-request",
        ServiceClientLifecycleOutcome.NotFound => "not-found",
        ServiceClientLifecycleOutcome.Conflict => "conflict",
        ServiceClientLifecycleOutcome.Expired => "expired",
        ServiceClientLifecycleOutcome.Revoked => "revoked",
        ServiceClientLifecycleOutcome.Unavailable => "unavailable",
        ServiceClientLifecycleOutcome.Throttled => "throttled",
        _ => throw new ArgumentOutOfRangeException(nameof(outcome), "Unsupported service-client lifecycle outcome.")
    };

    private static string AuthenticationOutcomeValue(ServiceClientAuthenticationOutcome outcome) => outcome switch
    {
        ServiceClientAuthenticationOutcome.Succeeded => "succeeded",
        ServiceClientAuthenticationOutcome.InvalidCredential => "invalid-credential",
        ServiceClientAuthenticationOutcome.Throttled => "throttled",
        ServiceClientAuthenticationOutcome.Unavailable => "unavailable",
        _ => throw new ArgumentOutOfRangeException(nameof(outcome), "Unsupported service-client authentication outcome.")
    };

    private static string ScopeValue(ServiceClientScope? scope) => scope is null
        ? "none"
        : ServiceClientScopeValues.ToExternalValue(scope.Value);
}
