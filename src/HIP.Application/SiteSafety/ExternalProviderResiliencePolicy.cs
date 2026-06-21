using System.Collections.Concurrent;

namespace HIP.Application.SiteSafety;

/// <summary>
/// Executes external provider calls behind circuit breaker and bulkhead controls.
/// </summary>
public interface IExternalProviderResiliencePolicy
{
    /// <summary>
    /// Executes provider work if the provider circuit is closed and bulkhead capacity is available.
    /// </summary>
    /// <typeparam name="T">Result type returned by the provider.</typeparam>
    /// <param name="providerName">Provider name used for circuit isolation.</param>
    /// <param name="operation">Provider operation to execute.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>Provider result.</returns>
    Task<T> ExecuteAsync<T>(string providerName, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken);
}

/// <summary>
/// Exception thrown when an external provider is temporarily isolated by the circuit breaker.
/// </summary>
/// <param name="providerName">Provider name.</param>
public sealed class ExternalProviderCircuitOpenException(string providerName)
    : InvalidOperationException($"{providerName} is temporarily isolated after repeated provider failures.")
{
}

/// <summary>
/// In-memory provider resilience policy for local and single-node MVP deployments.
/// </summary>
/// <remarks>
/// Production deployments should replace this with distributed resilience primitives, but the policy shape already
/// isolates providers so SSL Labs, Web Risk, VirusTotal, or future scanners cannot exhaust the whole application.
/// Updated 2026-06-21 10:13 UTC by HIP Development Team. Assisted by Codex.
/// The policy now uses <see cref="TimeProvider"/> so circuit-breaker behavior can be tested without sleeping.
/// </remarks>
public sealed class InMemoryExternalProviderResiliencePolicy : IExternalProviderResiliencePolicy
{
    private const int FailureThreshold = 3;
    private static readonly TimeSpan BreakDuration = TimeSpan.FromMinutes(1);
    private readonly TimeProvider timeProvider;
    private readonly ConcurrentDictionary<string, ProviderCircuitState> states = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Creates an in-memory resilience policy for external provider calls.
    /// </summary>
    /// <param name="timeProvider">Clock used to decide when provider circuits open and close.</param>
    public InMemoryExternalProviderResiliencePolicy(TimeProvider? timeProvider = null)
    {
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<T> ExecuteAsync<T>(string providerName, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        var state = states.GetOrAdd(providerName, _ => new ProviderCircuitState());
        if (state.IsOpen(timeProvider.GetUtcNow()))
        {
            throw new ExternalProviderCircuitOpenException(providerName);
        }

        await state.Bulkhead.WaitAsync(cancellationToken);
        try
        {
            var result = await operation(cancellationToken);
            state.RecordSuccess();
            return result;
        }
        catch
        {
            state.RecordFailure(timeProvider.GetUtcNow());
            throw;
        }
        finally
        {
            state.Bulkhead.Release();
        }
    }

    /// <summary>
    /// Per-provider circuit and bulkhead state.
    /// </summary>
    private sealed class ProviderCircuitState
    {
        private readonly object gate = new();
        private int failureCount;
        private DateTimeOffset? circuitOpenUntilUtc;

        /// <summary>
        /// Gets a small provider-specific bulkhead so slow external scanners cannot consume all worker capacity.
        /// </summary>
        public SemaphoreSlim Bulkhead { get; } = new(4, 4);

        /// <summary>
        /// Checks whether the provider circuit is currently open.
        /// </summary>
        /// <param name="now">Current UTC time.</param>
        /// <returns>True when calls should be rejected temporarily.</returns>
        public bool IsOpen(DateTimeOffset now)
        {
            lock (gate)
            {
                if (circuitOpenUntilUtc is null)
                {
                    return false;
                }

                if (circuitOpenUntilUtc <= now)
                {
                    circuitOpenUntilUtc = null;
                    failureCount = 0;
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Resets failure state after a successful provider call.
        /// </summary>
        public void RecordSuccess()
        {
            lock (gate)
            {
                failureCount = 0;
                circuitOpenUntilUtc = null;
            }
        }

        /// <summary>
        /// Records a failed provider call and opens the circuit after repeated failures.
        /// </summary>
        /// <param name="now">Current UTC time.</param>
        public void RecordFailure(DateTimeOffset now)
        {
            lock (gate)
            {
                failureCount++;
                if (failureCount >= FailureThreshold)
                {
                    circuitOpenUntilUtc = now.Add(BreakDuration);
                }
            }
        }
    }
}
