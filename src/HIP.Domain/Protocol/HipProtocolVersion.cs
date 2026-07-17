namespace HIP.Domain.Protocol;

public readonly record struct HipProtocolVersion
{
    public const string CurrentValue = "1.0";
    public const int MaximumLength = 8;

    private HipProtocolVersion(string value)
    {
        Value = value;
    }

    public string Value { get; }

    public bool IsSupported => string.Equals(Value, CurrentValue, StringComparison.Ordinal);

    public static HipProtocolVersion Current => new(CurrentValue);

    public static HipProtocolVersion Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaximumLength ||
            !string.Equals(value, CurrentValue, StringComparison.Ordinal))
        {
            throw new NotSupportedException($"HIP protocol version is malformed or unsupported. Supported version: {CurrentValue}.");
        }

        return new HipProtocolVersion(value!);
    }

    public override string ToString() => Value;
}
