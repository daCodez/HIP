using System.Security.Cryptography;
using System.Text;
using HIP.Application.Devices;

namespace HIP.Tests.Devices;

[TestFixture]
public sealed class Es256DeviceProofVerifierTests
{
    private readonly Es256DeviceProofVerifier verifier = new();

    [Test]
    public void Node_webcrypto_fixture_verifies_without_signature_conversion()
    {
        const string publicKey =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESzYtas4yXVfOwoAioti89GjZs07TjIEJMce62-fBlyLX8E4hgxzue6pS40L32qsrsmbpBYD2WIV7ba0Auka0AA";
        const string signingInput =
            "eyJhbGdvcml0aG0iOiJFQ0RTQS1QMjU2LVNIQTI1NiIsImNoYWxsZW5nZUlkIjoiZHJjX3dlYmNyeXB0b19maXh0dXJlIiwicHVycG9zZSI6ImRldmljZS1yZWdpc3RyYXRpb24iLCJ2ZXJzaW9uIjoiaGlwLWRldmljZS1yZWdpc3RyYXRpb24tcHJvb2YtdjEifQ";
        const string signature =
            "BXTIjYc3zVvhDDa3SvcFu1QCuMAhzOi9CW-7kZ-6L9T6mooIbZtKE5iyHoUyN_c6n_6h7AcBHYHF8Y554O5BwA";
        var validated = verifier.ValidatePublicKey(Es256DeviceProofVerifier.Algorithm, publicKey);

        Assert.That(
            verifier.VerifySignature(validated, Base64UrlDecode(signingInput), signature),
            Is.True);
    }

    [Test]
    public void Valid_p256_spki_is_canonicalized_and_fingerprinted()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = Base64UrlEncode(key.ExportSubjectPublicKeyInfo());

        var validated = verifier.ValidatePublicKey(Es256DeviceProofVerifier.Algorithm, publicKey);

        Assert.Multiple(() =>
        {
            Assert.That(validated.Algorithm, Is.EqualTo(Es256DeviceProofVerifier.Algorithm));
            Assert.That(validated.PublicKey, Is.EqualTo(publicKey));
            Assert.That(validated.PublicKeyFingerprint, Does.StartWith("sha256:"));
            Assert.That(validated.PublicKeyFingerprint, Has.Length.EqualTo(50));
        });
    }

    [Test]
    public void Webcrypto_compatible_p1363_signature_verifies_exact_payload()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validated = verifier.ValidatePublicKey(
            Es256DeviceProofVerifier.Algorithm,
            Base64UrlEncode(key.ExportSubjectPublicKeyInfo()));
        const string signingPayload =
            "{\"algorithm\":\"ECDSA-P256-SHA256\",\"challenge\":\"challenge\",\"type\":\"hip-device-registration-challenge\",\"version\":\"1\"}";
        var signingInput = Encoding.UTF8.GetBytes(signingPayload);
        var signature = Base64UrlEncode(key.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Assert.Multiple(() =>
        {
            Assert.That(verifier.VerifySignature(validated, signingInput, signature), Is.True);
            Assert.That(
                verifier.VerifySignature(validated, Encoding.UTF8.GetBytes(signingPayload + " "), signature),
                Is.False);
        });
    }

    [Test]
    public void Exact_algorithm_curve_and_public_only_spki_are_required()
    {
        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var p256Public = Base64UrlEncode(p256.ExportSubjectPublicKeyInfo());

        Assert.Multiple(() =>
        {
            Assert.That(
                () => verifier.ValidatePublicKey("es256", p256Public),
                Throws.TypeOf<NotSupportedException>());
            Assert.That(
                () => verifier.ValidatePublicKey(
                    Es256DeviceProofVerifier.Algorithm,
                    Base64UrlEncode(p384.ExportSubjectPublicKeyInfo())),
                Throws.TypeOf<ArgumentException>());
            Assert.That(
                () => verifier.ValidatePublicKey(
                    Es256DeviceProofVerifier.Algorithm,
                    Base64UrlEncode(p256.ExportPkcs8PrivateKey())),
                Throws.TypeOf<ArgumentException>());
        });
    }

    [Test]
    public void Public_key_encoding_must_be_canonical_bounded_base64url()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = Base64UrlEncode(key.ExportSubjectPublicKeyInfo());

        Assert.Multiple(() =>
        {
            Assert.That(
                () => verifier.ValidatePublicKey(Es256DeviceProofVerifier.Algorithm, publicKey + "="),
                Throws.TypeOf<ArgumentException>());
            Assert.That(
                () => verifier.ValidatePublicKey(
                    Es256DeviceProofVerifier.Algorithm,
                    new string('A', Es256DeviceProofVerifier.MaximumEncodedPublicKeyCharacters + 1)),
                Throws.TypeOf<ArgumentException>());
            Assert.That(
                () => verifier.ValidatePublicKey(Es256DeviceProofVerifier.Algorithm, "not+base64"),
                Throws.TypeOf<ArgumentException>());
        });
    }

    [TestCase("")]
    [TestCase("not+base64")]
    [TestCase("AQ")]
    public void Malformed_or_wrong_length_signature_fails_closed(string signature)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validated = verifier.ValidatePublicKey(
            Es256DeviceProofVerifier.Algorithm,
            Base64UrlEncode(key.ExportSubjectPublicKeyInfo()));

        Assert.That(verifier.VerifySignature(validated, "payload"u8, signature), Is.False);
    }

    [Test]
    public void Oversized_signing_payload_fails_closed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var validated = verifier.ValidatePublicKey(
            Es256DeviceProofVerifier.Algorithm,
            Base64UrlEncode(key.ExportSubjectPublicKeyInfo()));

        Assert.That(
            verifier.VerifySignature(
                validated,
                new byte[Es256DeviceProofVerifier.MaximumSigningPayloadBytes + 1],
                new string('A', 86)),
            Is.False);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight(base64.Length + ((4 - base64.Length % 4) % 4), '='));
    }
}
