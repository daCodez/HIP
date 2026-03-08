using BenchmarkDotNet.Attributes;
using HIP.Protocol.Benchmarks.Config;
using HIP.Protocol.Benchmarks.Data;

namespace HIP.Protocol.Benchmarks.Benchmarks;

[Config(typeof(HipBenchmarkConfig))]
[MemoryDiagnoser]
public class FailurePathProtocolBenchmarks
{
    private readonly DeterministicInputs _inputs = new();

    [Params(1024)]
    public int PayloadBytes { get; set; }

    [Benchmark]
    public async Task<bool> InvalidSignatureRejected()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var env = _inputs.CreateSignedEnvelope(PayloadBytes) with { Signature = "00" };
        var result = await svc.VerifyAsync(env, "key-sender");
        return result.Success;
    }

    [Benchmark]
    public async Task<bool> ReplayRejected()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var env = _inputs.CreateSignedEnvelope(PayloadBytes);
        _ = await svc.VerifyAsync(env, "key-sender");
        var replay = await svc.VerifyAsync(env, "key-sender");
        return replay.Success;
    }

    [Benchmark]
    public async Task<bool> ExpiredTimestampRejected()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var env = _inputs.CreateSignedEnvelope(PayloadBytes) with { TimestampUtc = _inputs.FixedUtc.AddHours(-2) };
        var result = await svc.VerifyAsync(env, "key-sender");
        return result.Success;
    }

    [Benchmark]
    public async Task<bool> MalformedEnvelopeRejected()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var env = _inputs.CreateSignedEnvelope(PayloadBytes) with { Nonce = string.Empty };
        var result = await svc.VerifyAsync(env, "key-sender");
        return result.Success;
    }
}
