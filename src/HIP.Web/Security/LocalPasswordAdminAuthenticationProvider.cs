using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Verifies the single local-development administrator stored in configuration and user secrets.
/// </summary>
public sealed class LocalPasswordAdminAuthenticationProvider(
    IOptions<HipAdminLoginOptions> configuredOptions,
    IPasswordHasher<string> passwordHasher)
    : IHipAdminAuthenticationProvider
{
    /// <inheritdoc />
    public ValueTask<HipAdminAuthenticationResult> AuthenticateAsync(
        HipAdminAuthenticationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var email = request.Email.Trim();
        var options = configuredOptions.Value;
        var inputIsReasonable =
            email.Length is > 0 and <= 254 &&
            request.Password.Length is > 0 and <= 256;

        if (!inputIsReasonable || string.IsNullOrWhiteSpace(options.PasswordHash))
        {
            return ValueTask.FromResult(HipAdminAuthenticationResult.Failed);
        }

        // Verify the password before comparing the account name so failure timing does not disclose
        // whether a submitted email matches the configured local administrator.
        var passwordMatches =
            passwordHasher.VerifyHashedPassword(options.Email, options.PasswordHash, request.Password) !=
            PasswordVerificationResult.Failed;
        var emailMatches = string.Equals(email, options.Email, StringComparison.OrdinalIgnoreCase);

        if (!emailMatches || !passwordMatches)
        {
            return ValueTask.FromResult(HipAdminAuthenticationResult.Failed);
        }

        var identity = new HipAdminIdentity(
            options.Email,
            options.Email,
            options.Email,
            AdminRoles.Owner);
        return ValueTask.FromResult(HipAdminAuthenticationResult.Success(identity));
    }
}
