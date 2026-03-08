using HIP.Protocol.Contracts;

namespace HIP.Protocol.Security.Abstractions;

public interface IHipSigner
{
    string Sign(string canonicalPayload, string keyId);
}

public interface IHipSignatureVerifier
{
    bool Verify(string canonicalPayload, string signature, string keyId);
}

public interface IHipKeyResolver
{
    bool KeyExists(string keyId);
}

public interface IHipReplayGuard
{
    Task<bool> IsReplayAsync(string senderHipId, string nonce, DateTimeOffset timestampUtc, CancellationToken ct = default);
}

public interface IHipTimestampPolicy
{
    bool IsWithinAllowedSkew(DateTimeOffset timestampUtc, DateTimeOffset nowUtc);
}

public interface IHipRevocationChecker
{
    bool IsRevoked(string keyId);
}

public sealed record HipVerificationOutcome(bool Success, HipError? Error = null);
