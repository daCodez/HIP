using System.Text.Json;
using HIP.Protocol.Canonicalization;
using HIP.Protocol.Security.Abstractions;
using HIP.Protocol.Security.Services;

namespace HIP.Protocol.Tests.Conformance;

public class HipConformanceFixtureTests
{
    [Test]
    public void HmacVector_ShouldMatchExpectedHashAndSignature()
    {
        var fixture = LoadFixture("conformance-vector-hmac.json");
        var hasher = new Sha256PayloadHasher();
        var signer = new HmacHipSigner(new Dictionary<string, string> { [fixture.KeyId] = fixture.Secret });

        var payloadHash = hasher.ComputePayloadHash(fixture.Payload!);
        var signature = signer.Sign(fixture.Canonical, fixture.KeyId);

        Assert.That(payloadHash, Is.EqualTo(fixture.ExpectedPayloadHash));
        Assert.That(signature, Is.EqualTo(fixture.ExpectedSignature));
    }

    [Test]
    public void ReceiptHmacVector_ShouldMatchExpectedSignature()
    {
        var fixture = LoadFixture("conformance-vector-receipt-hmac.json");
        var signer = new HmacHipSigner(new Dictionary<string, string> { [fixture.KeyId] = fixture.Secret });

        var signature = signer.Sign(fixture.Canonical, fixture.KeyId);

        Assert.That(signature, Is.EqualTo(fixture.ExpectedSignature));
    }

    [Test]
    public void Ed25519Rfc8032Vector_ShouldVerify()
    {
        var fixturePath = ResolvePath("conformance-vector-ed25519-rfc8032.json");
        var fixture = JsonSerializer.Deserialize<Ed25519Fixture>(File.ReadAllText(fixturePath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

        var privateKey = Convert.FromHexString(fixture.PrivateKeyHex);
        var publicKey = Convert.FromHexString(fixture.PublicKeyHex);
        var expectedSignature = Convert.FromHexString(fixture.ExpectedSignatureHex);

        var material = Ed25519KeyMaterial.FromRawKeyPair(privateKey, publicKey);
        var key = new HipSigningKey("ed25519-rfc", "ED25519", material);
        var provider = new Ed25519AlgorithmProvider();

        var signatureB64 = provider.Sign(fixture.Canonical, key);
        var signature = Convert.FromBase64String(signatureB64);

        Assert.That(signature, Is.EqualTo(expectedSignature));
        Assert.That(provider.Verify(fixture.Canonical, signatureB64, key), Is.EqualTo(true));
    }

    private static Fixture LoadFixture(string fileName)
    {
        var fixturePath = ResolvePath(fileName);
        return JsonSerializer.Deserialize<Fixture>(File.ReadAllText(fixturePath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
    }

    private static string ResolvePath(string fileName)
    {
        var fixturePath = Path.Combine(TestContext.CurrentContext.TestDirectory, "Conformance", fileName);
        if (!File.Exists(fixturePath))
        {
            fixturePath = Path.GetFullPath(Path.Combine(TestContext.CurrentContext.TestDirectory, "..", "..", "..", "..", "Conformance", fileName));
        }

        return fixturePath;
    }

    private sealed record Fixture(
        string Name,
        string KeyId,
        string Secret,
        string? Payload,
        string Canonical,
        string? ExpectedPayloadHash,
        string ExpectedSignature);

    private sealed record Ed25519Fixture(
        string Name,
        string Algorithm,
        string PrivateKeyHex,
        string PublicKeyHex,
        string Canonical,
        string ExpectedSignatureHex);
}
