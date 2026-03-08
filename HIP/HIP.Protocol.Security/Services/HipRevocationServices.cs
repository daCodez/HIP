using HIP.Protocol.Security.Abstractions;

namespace HIP.Protocol.Security.Services;

public sealed class InMemoryRevocationChecker(IEnumerable<string>? revokedKeyIds = null) : IHipRevocationChecker
{
    private readonly HashSet<string> _revoked = new(revokedKeyIds ?? [], StringComparer.Ordinal);

    public bool IsRevoked(string keyId)
        => !string.IsNullOrWhiteSpace(keyId) && _revoked.Contains(keyId);

    public void Revoke(string keyId)
    {
        if (!string.IsNullOrWhiteSpace(keyId)) _revoked.Add(keyId);
    }

    public void Unrevoke(string keyId)
    {
        if (!string.IsNullOrWhiteSpace(keyId)) _revoked.Remove(keyId);
    }
}
