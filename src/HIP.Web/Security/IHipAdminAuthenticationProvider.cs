namespace HIP.Web.Security;

/// <summary>
/// Validates administrator credentials and maps a successful login to one HIP identity.
/// </summary>
/// <remarks>
/// Implementations own only identity verification. HIP continues to own request validation,
/// rate limiting, redirects, and session cookies so those protections remain consistent when
/// the backing authentication service changes.
/// </remarks>
public interface IHipAdminAuthenticationProvider
{
    /// <summary>
    /// Validates one credential request without persisting or logging its password.
    /// </summary>
    ValueTask<HipAdminAuthenticationResult> AuthenticateAsync(
        HipAdminAuthenticationRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Contains credentials supplied to an administrator authentication provider.
/// </summary>
/// <remarks>The password must remain request-scoped and must never be logged or stored.</remarks>
public sealed record HipAdminAuthenticationRequest(string Email, string Password);

/// <summary>
/// Represents the provider-neutral HIP identity created after successful verification.
/// </summary>
public sealed record HipAdminIdentity(string Subject, string Email, string DisplayName, string Role);

/// <summary>
/// Represents either an authenticated HIP administrator or a generic authentication failure.
/// </summary>
public sealed record HipAdminAuthenticationResult
{
    private HipAdminAuthenticationResult(bool isAuthenticated, HipAdminIdentity? identity)
    {
        IsAuthenticated = isAuthenticated;
        Identity = identity;
    }

    /// <summary>
    /// Gets whether the provider verified the credentials.
    /// </summary>
    public bool IsAuthenticated { get; }

    /// <summary>
    /// Gets the verified identity, or null when verification failed.
    /// </summary>
    public HipAdminIdentity? Identity { get; }

    /// <summary>
    /// Creates a successful provider result.
    /// </summary>
    public static HipAdminAuthenticationResult Success(HipAdminIdentity identity) =>
        new(true, identity ?? throw new ArgumentNullException(nameof(identity)));

    /// <summary>
    /// Gets the shared generic failure result.
    /// </summary>
    public static HipAdminAuthenticationResult Failed { get; } = new(false, null);
}
