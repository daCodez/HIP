using System.Collections.Concurrent;
using System.Security.Cryptography;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class InMemoryKeyRotationPolicy : IKeyRotationPolicy
{
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, KeyMaterial> _keys = new();
    private int _currentVersion = 1;
    /// <summary>
    /// Gets or sets the value associated with this public contract member.
    /// </summary>
    public int MinAcceptedVersion { get; private set; } = 1;

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public InMemoryKeyRotationPolicy()
    {
        var key = CreateKey(_currentVersion);
        _keys[key.KeyId] = key;
    }

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public KeyMaterial Current()
    {
        lock (_gate)
        {
            return _keys.Values.OrderByDescending(x => x.Version).First();
        }
    }

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="keyId">The keyId value used by this operation.</param>
    /// <param name="key)">The key) value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public bool TryGet(string keyId, out KeyMaterial key) => _keys.TryGetValue(keyId, out key!);

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="emergency">The emergency value used by this operation.</param>
    /// <returns>The operation result.</returns>
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
