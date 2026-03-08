using BenchmarkDotNet.Attributes;
using HIP.Protocol.Benchmarks.Config;
using HIP.Protocol.Benchmarks.Data;

namespace HIP.Protocol.Benchmarks.Benchmarks;

[Config(typeof(HipBenchmarkConfig))]
[MemoryDiagnoser]
public class FlowProtocolBenchmarks
{
    private readonly DeterministicInputs _inputs = new();

    [Params(128, 1024, 10240)]
    public int PayloadBytes { get; set; }

    [Benchmark]
    public async Task<bool> FullEnvelopeValidationFlow()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var env = _inputs.CreateSignedEnvelope(PayloadBytes);
        var result = await svc.VerifyAsync(env, "key-sender");
        return result.Success;
    }

    [Benchmark]
    public async Task<bool> ProtectedHttpRequestValidation()
    {
        var svc = _inputs.BuildEnvelopeService(replayEnabled: true);
        var env = _inputs.CreateSignedEnvelope(PayloadBytes, withDeviceId: true);
        var result = await svc.VerifyAsync(env, "key-sender");
        return result.Success;
    }

    [Benchmark]
    public bool HandshakeFlowSuccess()
    {
        var challenge = _inputs.ChallengeService.CreateChallenge("key-sender", "key-receiver");
        var proof = _inputs.ChallengeService.CreateProof(challenge, "key-sender", "key-sender");
        return _inputs.ChallengeService.VerifyProof(challenge, proof, "key-sender");
    }

    [Benchmark]
    public bool HandshakeFlowFailure()
    {
        var challenge = _inputs.ChallengeService.CreateChallenge("key-sender", "key-receiver");
        var proof = _inputs.ChallengeService.CreateProof(challenge, "key-sender", "key-sender") with { Signature = "tampered" };
        return _inputs.ChallengeService.VerifyProof(challenge, proof, "key-sender");
    }

    [Benchmark]
    public bool ChallengeResponseFlow()
    {
        var challenge = _inputs.ChallengeService.CreateChallenge("key-sender", "key-receiver");
        var proof = _inputs.ChallengeService.CreateProof(challenge, "key-sender", "key-sender");
        var ok = _inputs.ChallengeService.VerifyProof(challenge, proof, "key-sender");
        if (!ok) return false;

        var env = _inputs.CreateSignedEnvelope(PayloadBytes);
        var receipt = _inputs.ReceiptService.Issue(_inputs.CreateUnsignedReceipt(env), "hip-http-verifier");
        return _inputs.ReceiptService.Verify(receipt, "hip-http-verifier").Success;
    }

    [Benchmark]
    public bool TrustReceiptIssueAndVerify()
    {
        var env = _inputs.CreateSignedEnvelope(PayloadBytes);
        var receipt = _inputs.ReceiptService.Issue(_inputs.CreateUnsignedReceipt(env), "hip-http-verifier");
        return _inputs.ReceiptService.Verify(receipt, "hip-http-verifier").Success;
    }
}
