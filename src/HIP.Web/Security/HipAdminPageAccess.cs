using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace HIP.Web.Security;

/// <summary>
/// Represents an admin-page mutation that either ran with one authorized HIP actor or failed closed.
/// </summary>
/// <typeparam name="T">Mutation result type.</typeparam>
/// <param name="Succeeded">Whether identity, environment, and current-circuit authorization checks succeeded.</param>
/// <param name="Value">Mutation result when access succeeded.</param>
public readonly record struct HipAdminPageAccessResult<T>(bool Succeeded, T? Value);

/// <summary>
/// Runs direct interactive-server admin mutations only after binding the current actor and reauthorizing the circuit.
/// </summary>
public static class HipAdminPageAccess
{
    private const int MaximumPoliciesPerMutation = 8;

    /// <summary>Gets the non-disclosing message shown when an admin mutation cannot be authorized safely.</summary>
    public const string AccessUnavailableMessage =
        "HIP could not authorize this admin action. Sign in again and retry.";

    /// <summary>
    /// Reauthorizes the active circuit and invokes a mutation with the unique server-authenticated HIP actor.
    /// </summary>
    /// <typeparam name="T">Mutation result type.</typeparam>
    /// <param name="principal">Current circuit principal.</param>
    /// <param name="authorizationService">Authorization service used to revalidate the named policy.</param>
    /// <param name="environment">Host environment used to enforce development-only operation gates.</param>
    /// <param name="policyName">Named policy required immediately before the mutation.</param>
    /// <param name="operation">Mutation callback receiving the server-resolved actor.</param>
    /// <param name="developmentOnly">Whether the operation must fail closed outside Development.</param>
    /// <returns>A failed result without invoking <paramref name="operation" /> when any check fails.</returns>
    public static async Task<HipAdminPageAccessResult<T>> ExecuteAuthorizedAsync<T>(
        ClaimsPrincipal principal,
        IAuthorizationService authorizationService,
        IHostEnvironment environment,
        string policyName,
        Func<string, T> operation,
        bool developmentOnly = false)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authorizationService);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentNullException.ThrowIfNull(operation);

        if ((developmentOnly && !environment.IsDevelopment()) ||
            !HipAuthenticatedIdentity.TryResolveUniqueClaim(
                principal,
                HipAuthenticationClaimTypes.ActorId,
                out var actor))
        {
            return new HipAdminPageAccessResult<T>(false, default);
        }

        var authorization = await authorizationService
            .AuthorizeAsync(principal, null, policyName)
            .ConfigureAwait(false);
        return authorization.Succeeded
            ? new HipAdminPageAccessResult<T>(true, operation(actor))
            : new HipAdminPageAccessResult<T>(false, default);
    }

    /// <summary>
    /// Reauthorizes every named policy in order, then invokes one asynchronous mutation with the unique HIP actor.
    /// </summary>
    /// <typeparam name="T">Mutation result type.</typeparam>
    /// <param name="principal">Current circuit principal.</param>
    /// <param name="authorizationService">Authorization service used to revalidate every named policy.</param>
    /// <param name="environment">Host environment used to enforce development-only operation gates.</param>
    /// <param name="policyNames">Small, explicit policy set that must all succeed.</param>
    /// <param name="operation">Asynchronous callback receiving the server-resolved actor.</param>
    /// <param name="cancellationToken">Cancellation signal for the operation and authorization boundary.</param>
    /// <param name="developmentOnly">Whether the operation must fail closed outside Development.</param>
    /// <returns>A failed result without invoking <paramref name="operation" /> when identity or any policy fails.</returns>
    public static async Task<HipAdminPageAccessResult<T>> ExecuteAuthorizedAsync<T>(
        ClaimsPrincipal principal,
        IAuthorizationService authorizationService,
        IHostEnvironment environment,
        IReadOnlyCollection<string> policyNames,
        Func<string, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken,
        bool developmentOnly = false)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authorizationService);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(policyNames);
        ArgumentNullException.ThrowIfNull(operation);

        var policies = policyNames.ToArray();
        if (policies.Length is < 1 or > MaximumPoliciesPerMutation ||
            policies.Any(string.IsNullOrWhiteSpace) ||
            policies.Distinct(StringComparer.Ordinal).Count() != policies.Length)
        {
            throw new ArgumentException("Admin mutations require a small set of unique named policies.", nameof(policyNames));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if ((developmentOnly && !environment.IsDevelopment()) ||
            !HipAuthenticatedIdentity.TryResolveUniqueClaim(
                principal,
                HipAuthenticationClaimTypes.ActorId,
                out var actor))
        {
            return new HipAdminPageAccessResult<T>(false, default);
        }

        foreach (var policyName in policies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var authorization = await authorizationService
                .AuthorizeAsync(principal, null, policyName)
                .ConfigureAwait(false);
            if (!authorization.Succeeded)
            {
                return new HipAdminPageAccessResult<T>(false, default);
            }
        }

        var value = await operation(actor, cancellationToken).ConfigureAwait(false);
        return new HipAdminPageAccessResult<T>(true, value);
    }
}
