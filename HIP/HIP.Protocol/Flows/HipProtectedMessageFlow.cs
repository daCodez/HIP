using HIP.Protocol.Contracts;

namespace HIP.Protocol.Flows;

public sealed record HipProtectedMessage(
    HipMessageEnvelope Envelope,
    string Payload,
    string? Channel = null);

public sealed record HipProtectedMessageResult(
    bool Accepted,
    HipPolicyDecision Decision,
    HipTrustReceipt? Receipt,
    HipError? Error = null);
