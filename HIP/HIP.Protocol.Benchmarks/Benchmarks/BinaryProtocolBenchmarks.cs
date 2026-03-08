using BenchmarkDotNet.Attributes;
using HIP.Protocol.Benchmarks.Config;
using HIP.Protocol.Benchmarks.Data;
using HIP.Protocol.Contracts;

namespace HIP.Protocol.Benchmarks.Benchmarks;

[Config(typeof(HipBenchmarkConfig))]
[MemoryDiagnoser]
public class BinaryProtocolBenchmarks
{
    private readonly DeterministicInputs _inputs = new();

    [Params(1024, 10240)]
    public int PayloadBytes { get; set; }

    [Benchmark]
    public async Task<bool> VerifySignature_BinaryCanonical()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true, includeBinaryVersion: true);
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, withDeviceId: true, hipVersion: HipProtocolVersions.V1Binary);
        var result = await svc.VerifyAsync(env, "key-sender");
        return result.Success;
    }

    [Benchmark]
    public bool IssueAndVerifyReceipt_BinaryCanonical()
    {
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, withDeviceId: true, hipVersion: HipProtocolVersions.V1Binary);
        var unsigned = _inputs.CreateUnsignedReceipt(env) with { HipVersion = HipProtocolVersions.V1Binary };
        var receipt = _inputs.ReceiptService.Issue(unsigned, "hip-http-verifier");
        return _inputs.ReceiptService.Verify(receipt, "hip-http-verifier").Success;
    }
}
