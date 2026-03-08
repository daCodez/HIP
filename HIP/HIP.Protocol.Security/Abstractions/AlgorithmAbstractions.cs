using HIP.Protocol.Contracts;

namespace HIP.Protocol.Security.Abstractions;

public sealed record HipSigningKey(
    string KeyId,
    string Algorithm,
    object KeyMaterial,
    DateTimeOffset? NotBeforeUtc = null,
    DateTimeOffset? NotAfterUtc = null,
    bool Revoked = false,
    string? ReplacedByKeyId = null);

public interface IHipKeyStore
{
    bool TryGet(string keyId, out HipSigningKey key);
}

public interface IHipAlgorithmProvider
{
    string Algorithm { get; }
    string Sign(string canonicalPayload, HipSigningKey key);
    bool Verify(string canonicalPayload, string signature, HipSigningKey key);
}

public interface IHipKeyLifecycleValidator
{
    HipError? Validate(HipSigningKey key, DateTimeOffset atUtc, string? correlationId);
}
