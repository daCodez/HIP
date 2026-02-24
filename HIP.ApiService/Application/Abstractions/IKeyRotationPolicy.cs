namespace HIP.ApiService.Application.Abstractions;

public interface IKeyRotationPolicy
{
    KeyMaterial Current();
    bool TryGet(string keyId, out KeyMaterial key);
    KeyRotationResult Rotate(bool emergency);
    int MinAcceptedVersion { get; }
}

public sealed record KeyMaterial(string KeyId, int Version, byte[] Secret, DateTimeOffset CreatedAtUtc);
public sealed record KeyRotationResult(string KeyId, int Version, bool Emergency, DateTimeOffset RotatedAtUtc);
