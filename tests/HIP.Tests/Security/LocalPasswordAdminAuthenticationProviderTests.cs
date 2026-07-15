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
            Assert.That(result.Identity!.Subject, Is.EqualTo(Email));
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

    private static LocalPasswordAdminAuthenticationProvider CreateProvider(
        IPasswordHasher<string> passwordHasher,
        string passwordHash) =>
        new(
            Options.Create(new HipAdminLoginOptions
            {
                Email = Email,
                PasswordHash = passwordHash
            }),
            passwordHasher);
}
