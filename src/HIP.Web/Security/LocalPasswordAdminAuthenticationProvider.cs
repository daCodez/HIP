using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Verifies bounded local-development accounts stored in private configuration.
/// </summary>
public sealed class LocalPasswordAdminAuthenticationProvider(
    IOptions<HipAdminLoginOptions> configuredOptions,
    IPasswordHasher<string> passwordHasher)
    : IHipAdminAuthenticationProvider
{
    private const int MaximumAccounts = 25;

    /// <inheritdoc />
    public ValueTask<HipAdminAuthenticationResult> AuthenticateAsync(
        HipAdminAuthenticationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var email = request.Email?.Trim() ?? string.Empty;
        var password = request.Password ?? string.Empty;
        var inputIsReasonable = LocalEmailIsValid(email) && password.Length is > 0 and <= 256;
        var options = configuredOptions.Value;
        var accounts = ConfiguredAccounts(options);
        if (!inputIsReasonable || accounts.Length is 0 or > MaximumAccounts || !ConfigurationIsValid(accounts))
        {
            return ValueTask.FromResult(HipAdminAuthenticationResult.Failed);
        }

        var matches = accounts
            .Where(account => string.Equals(email, account.Email, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matches.Length > 1)
        {
            return ValueTask.FromResult(HipAdminAuthenticationResult.Failed);
        }

        // Always perform one password verification when accounts are configured so failure timing does not
        // disclose whether a submitted email matches a local account. Test personas deliberately use the
        // bootstrap Owner credential and always begin without privileged access.
        var personaCredential = accounts.FirstOrDefault(account =>
            string.Equals(account.Role, AdminRoles.Owner, StringComparison.OrdinalIgnoreCase));
        var verificationAccount = matches.SingleOrDefault() ?? personaCredential ?? accounts[0];
        var passwordMatches = passwordHasher.VerifyHashedPassword(
            verificationAccount.Email,
            verificationAccount.PasswordHash,
            password) != PasswordVerificationResult.Failed;
        if (!passwordMatches)
        {
            return ValueTask.FromResult(HipAdminAuthenticationResult.Failed);
        }

        if (matches.Length == 0)
        {
            if (!options.AllowTestPersonas || personaCredential is null)
            {
                return ValueTask.FromResult(HipAdminAuthenticationResult.Failed);
            }

            return ValueTask.FromResult(HipAdminAuthenticationResult.Success(new HipAdminIdentity(
                HipDevelopmentActorId.FromSubject(email),
                email,
                "Local test persona",
                AdminRoles.ReadOnly)));
        }

        var account = matches[0];
        var identity = new HipAdminIdentity(
            HipDevelopmentActorId.FromSubject(account.Email),
            account.Email,
            account.DisplayName,
            account.Role);
        return ValueTask.FromResult(HipAdminAuthenticationResult.Success(identity));
    }

    private static ConfiguredLocalAccount[] ConfiguredAccounts(HipAdminLoginOptions options)
    {
        var configured = (options.Accounts ?? [])
            .Select(account => new ConfiguredLocalAccount(
                account.Email?.Trim() ?? string.Empty,
                string.IsNullOrWhiteSpace(account.DisplayName) ? "Local HIP user" : account.DisplayName.Trim(),
                account.PasswordHash ?? string.Empty,
                account.Role?.Trim() ?? string.Empty))
            .ToList();

        var legacyEmail = options.Email?.Trim() ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(legacyEmail) &&
            !configured.Any(account => string.Equals(account.Email, legacyEmail, StringComparison.OrdinalIgnoreCase)))
        {
            configured.Add(new ConfiguredLocalAccount(
                legacyEmail,
                "Initial HIP owner",
                options.PasswordHash ?? string.Empty,
                AdminRoles.Owner));
        }

        return configured.ToArray();
    }

    private static bool LocalEmailIsValid(string email) =>
        email.Length is > 3 and <= 254 &&
        email.Count(character => character == '@') == 1 &&
        !email.StartsWith('@') && !email.EndsWith('@') &&
        !email.Any(character => char.IsControl(character) || char.IsWhiteSpace(character));

    private static bool ConfigurationIsValid(IReadOnlyCollection<ConfiguredLocalAccount> accounts) =>
        accounts.Select(account => account.Email).Distinct(StringComparer.OrdinalIgnoreCase).Count() == accounts.Count &&
        accounts.All(account =>
            account.Email.Length is > 0 and <= 254 &&
            !string.IsNullOrWhiteSpace(account.PasswordHash) && account.PasswordHash.Length <= 1024 &&
            account.DisplayName.Length is >= 2 and <= 80 && !account.DisplayName.Contains('@') &&
            !account.DisplayName.Any(char.IsControl) &&
            AdminRoles.All.Contains(account.Role));

    private sealed record ConfiguredLocalAccount(
        string Email,
        string DisplayName,
        string PasswordHash,
        string Role);
}
