using HIP.Web.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies the local password provider obeys HIP's replaceable administrator authentication contract.
/// </summary>
public sealed class LocalPasswordAdminAuthenticationProviderTests
{
    private const string Email = "owner@hip.test";
    private const string Password = "test-password-only";

    [Test]
    public async Task Correct_credentials_return_owner_identity()
    {
        var passwordHasher = new PasswordHasher<string>();
        var provider = CreateProvider(passwordHasher, passwordHasher.HashPassword(Email, Password));

        var result = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(Email, Password),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAuthenticated, Is.True);
            Assert.That(result.Identity, Is.Not.Null);
            Assert.That(result.Identity!.Subject, Does.Match("^hip-user:v1:[0-9a-f]{64}$"));
            Assert.That(result.Identity.Subject, Does.Not.Contain("@").And.Not.Contain(Email));
            Assert.That(result.Identity.Email, Is.EqualTo(Email));
            Assert.That(result.Identity.Role, Is.EqualTo(AdminRoles.Owner));
        });
    }

    [Test]
    public async Task Incorrect_credentials_return_generic_failure_without_identity()
    {
        var passwordHasher = new PasswordHasher<string>();
        var provider = CreateProvider(passwordHasher, passwordHasher.HashPassword(Email, Password));

        var result = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(Email, "not-the-password"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsAuthenticated, Is.False);
            Assert.That(result.Identity, Is.Null);
        });
    }

    [Test]
    public async Task Missing_password_hash_fails_closed()
    {
        var provider = CreateProvider(new PasswordHasher<string>(), string.Empty);

        var result = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(Email, Password),
            CancellationToken.None);

        Assert.That(result.IsAuthenticated, Is.False);
    }

    [Test]
    public async Task Configured_accounts_receive_distinct_stable_actor_ids_and_roles()
    {
        const string analystEmail = "analyst@hip.test";
        const string analystPassword = "analyst-password-only";
        var passwordHasher = new PasswordHasher<string>();
        var provider = CreateProvider(
            passwordHasher,
            new HipAdminLoginOptions
            {
                Accounts =
                [
                    new HipAdminLocalAccountOptions
                    {
                        Email = Email,
                        DisplayName = "Primary owner",
                        PasswordHash = passwordHasher.HashPassword(Email, Password),
                        Role = AdminRoles.Owner
                    },
                    new HipAdminLocalAccountOptions
                    {
                        Email = analystEmail,
                        DisplayName = "Review analyst",
                        PasswordHash = passwordHasher.HashPassword(analystEmail, analystPassword),
                        Role = AdminRoles.ReadOnly
                    }
                ]
            });

        var owner = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(Email, Password), CancellationToken.None);
        var analyst = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(analystEmail, analystPassword), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(owner.IsAuthenticated, Is.True);
            Assert.That(analyst.IsAuthenticated, Is.True);
            Assert.That(owner.Identity!.Subject, Is.Not.EqualTo(analyst.Identity!.Subject));
            Assert.That(owner.Identity.Role, Is.EqualTo(AdminRoles.Owner));
            Assert.That(analyst.Identity.Role, Is.EqualTo(AdminRoles.ReadOnly));
        });
    }

    [Test]
    public async Task Opted_in_test_emails_use_owner_password_but_start_unprivileged()
    {
        const string personaEmail = "different-browser-user@hip.test";
        var passwordHasher = new PasswordHasher<string>();
        var options = new HipAdminLoginOptions
        {
            Email = Email,
            PasswordHash = passwordHasher.HashPassword(Email, Password),
            AllowTestPersonas = true
        };
        var provider = CreateProvider(passwordHasher, options);

        var persona = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(personaEmail, Password), CancellationToken.None);
        var repeated = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(personaEmail, Password), CancellationToken.None);
        var owner = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(Email, Password), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(persona.IsAuthenticated, Is.True);
            Assert.That(persona.Identity!.Role, Is.EqualTo(AdminRoles.ReadOnly));
            Assert.That(persona.Identity.Subject, Is.EqualTo(repeated.Identity!.Subject));
            Assert.That(persona.Identity.Subject, Is.Not.EqualTo(owner.Identity!.Subject));
            Assert.That(persona.Identity.Subject, Does.Not.Contain(personaEmail));
        });
    }

    [Test]
    public async Task Unknown_email_still_fails_when_test_personas_are_disabled()
    {
        var passwordHasher = new PasswordHasher<string>();
        var provider = CreateProvider(passwordHasher, passwordHasher.HashPassword(Email, Password));

        var result = await provider.AuthenticateAsync(
            new HipAdminAuthenticationRequest("other@hip.test", Password), CancellationToken.None);

        Assert.That(result.IsAuthenticated, Is.False);
    }

    private static LocalPasswordAdminAuthenticationProvider CreateProvider(
        IPasswordHasher<string> passwordHasher,
        string passwordHash) =>
        CreateProvider(
            passwordHasher,
            new HipAdminLoginOptions
            {
                Email = Email,
                PasswordHash = passwordHash
            });

    private static LocalPasswordAdminAuthenticationProvider CreateProvider(
        IPasswordHasher<string> passwordHasher,
        HipAdminLoginOptions options) =>
        new(Options.Create(options), passwordHasher);
}
