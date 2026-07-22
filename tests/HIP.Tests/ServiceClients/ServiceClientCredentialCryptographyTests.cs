using System.Security.Cryptography;
using System.Text;
using HIP.Application.ServiceClients;

namespace HIP.Tests.ServiceClients;

[TestFixture]
[Parallelizable(ParallelScope.None)]
public sealed class ServiceClientCredentialCryptographyTests
{
    [Test]
    public void Generator_returns_canonical_high_entropy_identifier_and_wrapped_secret()
    {
        var generator = new CryptographicServiceClientCredentialGenerator();

        var clientId = generator.GenerateClientId();
        var secret = generator.GenerateSecret();
        var secretValue = secret.Reveal();

        Assert.Multiple(() =>
        {
            Assert.That(clientId, Does.StartWith("hipc_v1_"));
            Assert.That(DecodeCanonicalBase64Url(clientId["hipc_v1_".Length..]), Has.Length.EqualTo(16));
            Assert.That(secret, Is.TypeOf<ServiceClientSecret>());
            Assert.That(secretValue.Length, Is.EqualTo("hips_v1_".Length + 43));
            Assert.That(secretValue.StartsWith("hips_v1_", StringComparison.Ordinal), Is.True);
            Assert.That(DecodeCanonicalBase64Url(secretValue["hips_v1_".Length..]), Has.Length.EqualTo(32));
            Assert.That(secret.ToString(), Is.EqualTo("[REDACTED]"));
        });
    }

    [Test]
    public void Generator_does_not_reuse_identifiers_or_secrets_within_a_bounded_sample()
    {
        var generator = new CryptographicServiceClientCredentialGenerator();
        var clientIds = Enumerable.Range(0, 64)
            .Select(_ => generator.GenerateClientId())
            .ToArray();
        var secrets = Enumerable.Range(0, 64)
            .Select(_ => generator.GenerateSecret().Reveal())
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(clientIds.Distinct(StringComparer.Ordinal).ToArray(), Has.Length.EqualTo(clientIds.Length));
            Assert.That(secrets.Distinct(StringComparer.Ordinal).ToArray(), Has.Length.EqualTo(secrets.Length));
        });
    }

    [Test]
    public void Protector_emits_the_exact_canonical_PBKDF2_SHA256_format_and_input_binding()
    {
        var generator = new CryptographicServiceClientCredentialGenerator();
        var protector = new Pbkdf2ServiceClientSecretProtector();
        var clientId = generator.GenerateClientId();
        var secret = generator.GenerateSecret();

        var verifier = protector.Protect(clientId, secret);
        var parts = verifier.Split('$');
        Assert.That(parts, Has.Length.EqualTo(4));
        var salt = DecodeCanonicalBase64Url(parts[2]);
        var protectedValue = DecodeCanonicalBase64Url(parts[3]);
        var passwordBytes = Encoding.UTF8.GetBytes(
            $"HIP-Service-Credential-v1\0{clientId}\0{secret.Reveal()}");
        var expected = Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes,
            salt,
            600_000,
            HashAlgorithmName.SHA256,
            32);

        try
        {
            Assert.Multiple(() =>
            {
                Assert.That(parts[0], Is.EqualTo("pbkdf2-sha256-v1"));
                Assert.That(parts[1], Is.EqualTo("600000"));
                Assert.That(salt, Has.Length.EqualTo(16));
                Assert.That(protectedValue, Has.Length.EqualTo(32));
                Assert.That(protectedValue, Is.EqualTo(expected));
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    [Test]
    public void Protector_uses_a_fresh_salt_for_each_protected_value()
    {
        var generator = new CryptographicServiceClientCredentialGenerator();
        var protector = new Pbkdf2ServiceClientSecretProtector();
        var clientId = generator.GenerateClientId();
        var secret = generator.GenerateSecret();

        var first = protector.Protect(clientId, secret);
        var second = protector.Protect(clientId, secret);

        Assert.Multiple(() =>
        {
            Assert.That(second, Is.Not.EqualTo(first));
            Assert.That(second.Split('$')[2], Is.Not.EqualTo(first.Split('$')[2]));
            Assert.That(protector.Verify(clientId, secret, first), Is.True);
            Assert.That(protector.Verify(clientId, secret, second), Is.True);
        });
    }

    [Test]
    public void Verification_is_bound_to_the_exact_client_identifier_and_secret()
    {
        var generator = new CryptographicServiceClientCredentialGenerator();
        var protector = new Pbkdf2ServiceClientSecretProtector();
        var clientId = generator.GenerateClientId();
        var secret = generator.GenerateSecret();
        var verifier = protector.Protect(clientId, secret);

        Assert.Multiple(() =>
        {
            Assert.That(protector.Verify(clientId, secret, verifier), Is.True);
            Assert.That(protector.Verify(generator.GenerateClientId(), secret, verifier), Is.False);
            Assert.That(protector.Verify(clientId, generator.GenerateSecret(), verifier), Is.False);
        });
    }

    [Test]
    public void Protect_rejects_noncanonical_credential_material_without_echoing_it()
    {
        var generator = new CryptographicServiceClientCredentialGenerator();
        var protector = new Pbkdf2ServiceClientSecretProtector();
        var secret = generator.GenerateSecret();

        var clientException = Assert.Throws<ArgumentException>(
            () => protector.Protect("hipc_v1_invalid", secret));
        var secretException = Assert.Throws<ArgumentException>(
            () => protector.Protect(generator.GenerateClientId(), new ServiceClientSecret("invalid")));

        Assert.Multiple(() =>
        {
            Assert.That(
                clientException!.Message,
                Does.StartWith("The service-client identifier is not in canonical form."));
            Assert.That(
                secretException!.Message,
                Does.StartWith("The service-client secret is not in canonical form."));
        });
    }

    [Test]
    public void Malformed_verifiers_and_credentials_return_false_without_throwing()
    {
        var generator = new CryptographicServiceClientCredentialGenerator();
        var protector = new Pbkdf2ServiceClientSecretProtector();
        var clientId = generator.GenerateClientId();
        var secret = generator.GenerateSecret();
        var canonicalSalt = new string('A', 22);
        var canonicalHash = new string('A', 43);
        var malformed = new string?[]
        {
            null,
            string.Empty,
            "pbkdf2-sha256-v1$600000",
            $"PBKDF2-SHA256-V1$600000${canonicalSalt}${canonicalHash}",
            $"pbkdf2-sha256-v1$0600000${canonicalSalt}${canonicalHash}",
            $"pbkdf2-sha256-v1$599999${canonicalSalt}${canonicalHash}",
            $"pbkdf2-sha256-v1$600000${canonicalSalt}=${canonicalHash}",
            $"pbkdf2-sha256-v1$600000${canonicalSalt}${canonicalHash}=",
            $"pbkdf2-sha256-v1$600000${new string('A', 21)}${canonicalHash}",
            $"pbkdf2-sha256-v1$600000${canonicalSalt[..^1]}B${canonicalHash}",
            $"pbkdf2-sha256-v1$600000${canonicalSalt}${new string('A', 42)}",
            $"pbkdf2-sha256-v1$600000${canonicalSalt}${canonicalHash}%",
            $"pbkdf2-sha256-v1$600000${canonicalSalt}${canonicalHash}$extra",
            new string('A', 1_025)
        };

        Assert.Multiple(() =>
        {
            foreach (var candidate in malformed)
            {
                Assert.That(
                    () => protector.Verify(clientId, secret, candidate!),
                    Throws.Nothing);
                Assert.That(protector.Verify(clientId, secret, candidate!), Is.False);
            }

            Assert.That(protector.Verify("hipc_v1_invalid", secret, malformed[2]!), Is.False);
            Assert.That(
                protector.Verify(clientId, new ServiceClientSecret("invalid"), malformed[2]!),
                Is.False);
        });
    }

    private static byte[] DecodeCanonicalBase64Url(string value)
    {
        Assert.That(value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_'), Is.True);
        Assert.That(value.Contains('='), Is.False);

        var base64 = value.Replace('-', '+').Replace('_', '/');
        var remainder = base64.Length % 4;
        if (remainder > 0)
        {
            base64 = base64.PadRight(base64.Length + 4 - remainder, '=');
        }

        var decoded = Convert.FromBase64String(base64);
        var canonical = Convert.ToBase64String(decoded)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        Assert.That(string.Equals(value, canonical, StringComparison.Ordinal), Is.True);
        return decoded;
    }
}
