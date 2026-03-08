using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using HIP.Protocol.Benchmarks.Config;
using HIP.Protocol.Benchmarks.Data;

namespace HIP.Protocol.Benchmarks.Benchmarks;

[Config(typeof(HipBenchmarkConfig))]
[MemoryDiagnoser]
public class MicroProtocolBenchmarks
{
    private readonly DeterministicInputs _inputs = new();

    [Params(128, 1024, 10240)]
    public int PayloadBytes { get; set; }

    [Params(false, true)]
    public bool WithDeviceId { get; set; }

    [Benchmark]
    public object CreateHipMessageEnvelope()
        => _inputs.CreateSignedEnvelope(PayloadBytes, WithDeviceId);

    [Benchmark]
    public string CanonicalSerializeEnvelope()
    {
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, WithDeviceId);
        return _inputs.Canonical.CanonicalizeEnvelope(env);
    }

    [Benchmark]
    public string HashPayload()
        => _inputs.Hasher.ComputePayloadHash(_inputs.PayloadOfSize(PayloadBytes));

    [Benchmark]
    public string SignEnvelope()
    {
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, WithDeviceId);
        var canonical = _inputs.Canonical.CanonicalizeEnvelope(env);
        return _inputs.HmacSigner.Sign(canonical, "key-sender");
    }

    [Benchmark]
    public bool VerifySignature()
    {
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, WithDeviceId);
        var canonical = _inputs.Canonical.CanonicalizeEnvelope(env);
        return _inputs.HmacSigner.Verify(canonical, env.Signature, "key-sender");
    }

    [Benchmark]
    public bool TimestampValidation()
    {
        var policy = new HIP.Protocol.Security.Services.HipTimestampPolicy(new HIP.Protocol.Security.Options.HipSecurityOptions { AllowedClockSkewSeconds = 300 });
        return policy.IsWithinAllowedSkew(_inputs.FixedUtc, _inputs.FixedUtc);
    }

    [Benchmark]
    public async Task<bool> NonceReplayCheck()
    {
        var guard = new HIP.Protocol.Security.Services.InMemoryReplayGuard(new HIP.Protocol.Security.Options.HipSecurityOptions { ReplayWindowSeconds = 600 });
        return await guard.IsReplayAsync("key-sender", Guid.NewGuid().ToString("N"), _inputs.FixedUtc);
    }

    [Benchmark]
    public object GenerateTrustReceipt()
    {
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, WithDeviceId);
        return _inputs.ReceiptService.Issue(_inputs.CreateUnsignedReceipt(env), "hip-http-verifier");
    }

    [Benchmark]
    public bool VerifyTrustReceipt()
    {
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, WithDeviceId);
        var receipt = _inputs.ReceiptService.Issue(_inputs.CreateUnsignedReceipt(env), "hip-http-verifier");
        return _inputs.ReceiptService.Verify(receipt, "hip-http-verifier").Success;
    }
}
