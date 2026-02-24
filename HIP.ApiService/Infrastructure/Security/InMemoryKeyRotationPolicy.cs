using System.Collections.Concurrent;
using System.Security.Cryptography;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemoryKeyRotationPolicy : IKeyRotationPolicy
{
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, KeyMaterial> _keys = new();
    private int _currentVersion = 1;
    public int MinAcceptedVersion { get; private set; } = 1;

    public InMemoryKeyRotationPolicy()
    {
        var key = CreateKey(_currentVersion);
        _keys[key.KeyId] = key;
    }

    public KeyMaterial Current()
    {
        lock (_gate)
        {
            return _keys.Values.OrderByDescending(x => x.Version).First();
        }
    }

    public bool TryGet(string keyId, out KeyMaterial key) => _keys.TryGetValue(keyId, out key!);

    public KeyRotationResult Rotate(bool emergency)
    {
        lock (_gate)
        {
            _currentVersion += 1;
            var key = CreateKey(_currentVersion);
            _keys[key.KeyId] = key;

            if (emergency)
            {
                MinAcceptedVersion = key.Version;
            }

            return new KeyRotationResult(key.KeyId, key.Version, emergency, DateTimeOffset.UtcNow);
        }
    }

    private static KeyMaterial CreateKey(int version)
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var keyId = $"jarvis-k{version}";
        return new KeyMaterial(keyId, version, secret, DateTimeOffset.UtcNow);
    }
}
