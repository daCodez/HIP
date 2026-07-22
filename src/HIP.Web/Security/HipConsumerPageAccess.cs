using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace HIP.Web.Security;

/// <summary>
/// Represents a consumer-page operation that either used one authenticated HIP consumer identifier or failed closed.
/// </summary>
/// <typeparam name="T">Operation result type.</typeparam>
/// <param name="Succeeded">Whether the caller had one usable HIP consumer identifier and any required authorization.</param>
/// <param name="Value">Operation result when access succeeded.</param>
public readonly record struct HipConsumerPageAccessResult<T>(bool Succeeded, T? Value);

/// <summary>
/// Runs consumer-page service calls only after resolving exactly one HIP-owned consumer identifier.
/// </summary>
public static class HipConsumerPageAccess
{
    /// <summary>Gets the non-disclosing message shown when a consumer page cannot bind the current account.</summary>
    public const string AccessUnavailableMessage =
        "HIP could not bind this page to your consumer account. Sign in again and retry.";

    /// <summary>
    /// Executes an asynchronous consumer service call with the unique authenticated consumer identifier.
    /// </summary>
    /// <typeparam name="T">Service result type.</typeparam>
    /// <param name="principal">Current authenticated principal.</param>
    /// <param name="operation">Service call that receives the server-resolved consumer identifier.</param>
    /// <returns>A failed result without invoking <paramref name="operation" /> when the claim is missing or ambiguous.</returns>
    public static async Task<HipConsumerPageAccessResult<T>> ExecuteAsync<T>(
        ClaimsPrincipal principal,
        Func<string, Task<T>> operation)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(operation);

        if (!TryResolveConsumerId(principal, out var consumerId))
        {
            return new HipConsumerPageAccessResult<T>(false, default);
        }

        return new HipConsumerPageAccessResult<T>(true, await operation(consumerId).ConfigureAwait(false));
    }

    /// <summary>
    /// Reauthorizes a consumer mutation and invokes it immediately with the unique authenticated consumer identifier.
    /// </summary>
    /// <typeparam name="T">Mutation result type.</typeparam>
    /// <param name="principal">Current authenticated principal.</param>
    /// <param name="authorizationService">Authorization service used to revalidate the active circuit.</param>
    /// <param name="policyName">Named policy required immediately before persistence.</param>
    /// <param name="operation">Mutation that receives the server-resolved consumer identifier.</param>
    /// <returns>A failed result without invoking <paramref name="operation" /> when identity or authorization fails.</returns>
    public static async Task<HipConsumerPageAccessResult<T>> ExecuteAuthorizedAsync<T>(
        ClaimsPrincipal principal,
        IAuthorizationService authorizationService,
        string policyName,
        Func<string, T> operation)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authorizationService);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentNullException.ThrowIfNull(operation);

        if (!TryResolveConsumerId(principal, out var consumerId))
        {
            return new HipConsumerPageAccessResult<T>(false, default);
        }

        var authorization = await authorizationService.AuthorizeAsync(principal, policyName).ConfigureAwait(false);
        return authorization.Succeeded
            ? new HipConsumerPageAccessResult<T>(true, operation(consumerId))
            : new HipConsumerPageAccessResult<T>(false, default);
    }

    /// <summary>
    /// Reauthorizes a consumer mutation and invokes its asynchronous persistence operation immediately afterward.
    /// </summary>
    public static async Task<HipConsumerPageAccessResult<T>> ExecuteAuthorizedAsync<T>(
        ClaimsPrincipal principal,
        IAuthorizationService authorizationService,
        string policyName,
        Func<string, Task<T>> operation)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authorizationService);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentNullException.ThrowIfNull(operation);

        if (!TryResolveConsumerId(principal, out var consumerId))
        {
            return new HipConsumerPageAccessResult<T>(false, default);
        }

        var authorization = await authorizationService.AuthorizeAsync(principal, policyName).ConfigureAwait(false);
        return authorization.Succeeded
            ? new HipConsumerPageAccessResult<T>(
                true,
                await operation(consumerId).ConfigureAwait(false))
            : new HipConsumerPageAccessResult<T>(false, default);
    }

    private static bool TryResolveConsumerId(ClaimsPrincipal principal, out string consumerId)
        => HipAuthenticatedIdentity.TryResolveUniqueClaim(
            principal,
            HipAuthenticationClaimTypes.ConsumerId,
            out consumerId);
}
