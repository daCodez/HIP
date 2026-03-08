using BenchmarkDotNet.Attributes;
using HIP.Protocol.Benchmarks.Config;
using HIP.Protocol.Canonicalization;
using HIP.Protocol.Contracts;
using HIP.Protocol.Security.Abstractions;
using HIP.Protocol.Security.Services;

namespace HIP.Protocol.Benchmarks.Benchmarks;

[Config(typeof(HipBenchmarkConfig))]
[MemoryDiagnoser]
public class AsymmetricProtocolBenchmarks
{
    private readonly HipCanonicalSerializer _canonical = new();
    private HipMessageEnvelope _ecdsaEnvelope = null!;
    private HipMessageEnvelope _edEnvelope = null!;

    private AlgorithmRouterSigner _ecdsaRouter = null!;
    private AlgorithmRouterSigner _edRouter = null!;

    private System.Security.Cryptography.ECDsa? _ecdsa;

    [GlobalSetup]
    public void Setup()
    {
        _ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new HipSigningKey("sender-ecdsa", "ECDSA_P256_SHA256", _ecdsa);
        var ecdsaStore = new InMemoryHipKeyStore([ecdsaKey]);
        _ecdsaRouter = new AlgorithmRouterSigner(ecdsaStore, [new EcdsaP256AlgorithmProvider()]);

        var edMaterial = Ed25519KeyMaterial.Generate();
        var edKey = new HipSigningKey("sender-ed", "ED25519", edMaterial);
        var edStore = new InMemoryHipKeyStore([edKey]);
        _edRouter = new AlgorithmRouterSigner(edStore, [new Ed25519AlgorithmProvider()]);

        _ecdsaEnvelope = BuildSigned(_ecdsaRouter, "sender-ecdsa", "payload-ecdsa");
        _edEnvelope = BuildSigned(_edRouter, "sender-ed", "payload-ed");
    }

    [Benchmark]
    public bool VerifySignature_EcdsaP256()
    {
        var canonical = _canonical.CanonicalizeEnvelope(_ecdsaEnvelope with { Signature = string.Empty });
        return _ecdsaRouter.Verify(canonical, _ecdsaEnvelope.Signature, "sender-ecdsa");
    }

    [Benchmark]
    public bool VerifySignature_Ed25519()
    {
        var canonical = _canonical.CanonicalizeEnvelope(_edEnvelope with { Signature = string.Empty });
        return _edRouter.Verify(canonical, _edEnvelope.Signature, "sender-ed");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _ecdsa?.Dispose();
    }

    private HipMessageEnvelope BuildSigned(IHipSigner signer, string sender, string payload)
    {
        var hasher = new Sha256PayloadHasher();
        var env = new HipMessageEnvelope("1.0", "ProtectedMessage", sender, "receiver-a", DateTimeOffset.UtcNow, Guid.NewGuid().ToString("N"), hasher.ComputePayloadHash(payload), string.Empty, Guid.NewGuid().ToString("N"));
        var canonical = _canonical.CanonicalizeEnvelope(env with { Signature = string.Empty });
        return env with { Signature = signer.Sign(canonical, sender) };
    }
}
