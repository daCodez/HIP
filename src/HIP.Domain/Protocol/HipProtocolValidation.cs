using System.Text.Json;

namespace HIP.Domain.Protocol;

internal static class HipProtocolValidation
{
    public static string RequiredIdentifier(string? value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("HIP protocol identifiers are required.", parameterName);
        }

        if (value.Length > maximumLength)
        {
            throw new ArgumentException($"HIP protocol identifiers cannot exceed {maximumLength} characters.", parameterName);
        }

        if (value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw new ArgumentException("HIP protocol identifiers cannot contain whitespace or control characters.", parameterName);
        }

        return value;
    }

    public static string RequiredToken(string? value, string parameterName, int maximumLength)
    {
        var token = RequiredIdentifier(value, parameterName, maximumLength);
        if (!token.All(character =>
                character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':'))
        {
            throw new ArgumentException("HIP protocol tokens may contain only letters, digits, hyphens, underscores, periods, and colons.", parameterName);
        }

        return token;
    }

    public static JsonElement RequiredJsonValue(JsonElement value, string parameterName, int maximumBytes)
    {
        if (value.ValueKind is JsonValueKind.Undefined)
        {
            throw new ArgumentException("HIP protocol claim values must be defined JSON values.", parameterName);
        }

        var clone = value.Clone();
        HipProtocolJsonShape.ValidateClaimValue(clone, parameterName);
        if (JsonSerializer.SerializeToUtf8Bytes(clone).Length > maximumBytes)
        {
            throw new ArgumentException($"HIP protocol claim values cannot exceed {maximumBytes} UTF-8 bytes.", parameterName);
        }

        return clone;
    }

    public static DateTimeOffset RequiredUtcTimestamp(DateTimeOffset value, string parameterName)
    {
        if (value.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("HIP protocol timestamps must use UTC.", parameterName);
        }

        if (value.Ticks % TimeSpan.TicksPerMillisecond != 0)
        {
            throw new ArgumentException("HIP protocol timestamps cannot be more precise than one millisecond.", parameterName);
        }

        return value;
    }
}
