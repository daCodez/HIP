using BenchmarkDotNet.Attributes;
using HIP.Protocol.Benchmarks.Config;
using HIP.Protocol.Benchmarks.Data;

namespace HIP.Protocol.Benchmarks.Benchmarks;

[Config(typeof(HipBenchmarkConfig))]
[MemoryDiagnoser]
public class ScaleProtocolBenchmarks
{
    private readonly DeterministicInputs _inputs = new();

    [Params(10, 100, 1000)]
    public int ConcurrentRequests { get; set; }

    [Benchmark]
    public async Task<int> Validate1000EnvelopesSequential()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var ok = 0;
        for (var i = 0; i < 1000; i++)
        {
            var env = _inputs.CreateSignedEnvelope(1024);
            var result = await svc.VerifyAsync(env, "key-sender");
            if (result.Success) ok++;
        }
        return ok;
    }

    [Benchmark]
    public async Task<int> Validate1000EnvelopesParallel()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var envelopes = Enumerable.Range(0, 1000).Select(_ => _inputs.CreateSignedEnvelope(1024)).ToArray();

        var sem = new SemaphoreSlim(ConcurrentRequests);
        var tasks = envelopes.Select(async env =>
        {
            await sem.WaitAsync();
            try
            {
                var result = await svc.VerifyAsync(env, "key-sender");
                return result.Success ? 1 : 0;
            }
            finally
            {
                sem.Release();
            }
        });

        var results = await Task.WhenAll(tasks);
        return results.Sum();
    }

    [Benchmark]
    public int Generate1000TrustReceipts()
    {
        var ok = 0;
        for (var i = 0; i < 1000; i++)
        {
            var env = _inputs.CreateSignedEnvelope(1024);
            var receipt = _inputs.ReceiptService.Issue(_inputs.CreateUnsignedReceipt(env), "hip-http-verifier");
            if (!string.IsNullOrWhiteSpace(receipt.ReceiptSignature)) ok++;
        }
        return ok;
    }

    [Benchmark]
    public int Verify1000TrustReceipts()
    {
        var receipts = new List<HIP.Protocol.Contracts.HipTrustReceipt>(1000);
        for (var i = 0; i < 1000; i++)
        {
            var env = _inputs.CreateSignedEnvelope(1024);
            receipts.Add(_inputs.ReceiptService.Issue(_inputs.CreateUnsignedReceipt(env), "hip-http-verifier"));
        }

        var ok = 0;
        foreach (var receipt in receipts)
        {
            if (_inputs.ReceiptService.Verify(receipt, "hip-http-verifier").Success) ok++;
        }

        return ok;
    }

    [Benchmark]
    public async Task<int> ReplayCacheUnderLoad()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var env = _inputs.CreateSignedEnvelope(1024);
        var first = await svc.VerifyAsync(env, "key-sender");
        var replayRejects = 0;

        for (var i = 0; i < 500; i++)
        {
            var replay = await svc.VerifyAsync(env, "key-sender");
            if (!replay.Success) replayRejects++;
        }

        return first.Success ? replayRejects : 0;
    }
}
