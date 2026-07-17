using System.Collections.ObjectModel;
using System.Text.Json;

namespace HIP.Domain.Protocol;

public sealed record HipProtocolClaim
{
    public const int MaximumNameLength = 64;
    public const int MaximumValueBytes = 4096;
    public const int MaximumValueDepth = 8;

    public HipProtocolClaim(string name, JsonElement value)
    {
        Name = HipProtocolValidation.RequiredToken(name, nameof(name), MaximumNameLength);
        Value = HipProtocolValidation.RequiredJsonValue(value, nameof(value), MaximumValueBytes);
    }

    public string Name { get; }

    public JsonElement Value { get; }
}

public sealed class HipProtocolClaims
{
    public const int MaximumCount = 32;

    public HipProtocolClaims(IReadOnlyDictionary<string, JsonElement> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count > MaximumCount)
        {
            throw new ArgumentException($"HIP protocol envelopes cannot contain more than {MaximumCount} claims.", nameof(values));
        }

        var sorted = new SortedDictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var pair in values)
        {
            var claim = new HipProtocolClaim(pair.Key, pair.Value);
            if (!sorted.TryAdd(claim.Name, claim.Value))
            {
                throw new ArgumentException($"HIP protocol claim '{claim.Name}' is duplicated.", nameof(values));
            }
        }

        Values = new ReadOnlyDictionary<string, JsonElement>(sorted);
    }

    public IReadOnlyDictionary<string, JsonElement> Values { get; }
}
