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

    public static string RequiredCanonicalBase64Url(
        string? value,
        string parameterName,
        int minimumBytes,
        int maximumBytes)
    {
        if (minimumBytes < 1 || maximumBytes < minimumBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumBytes),
                "Canonical base64url byte bounds are invalid.");
        }

        if (string.IsNullOrEmpty(value) ||
            value.Length > ((maximumBytes * 4) + 2) / 3 ||
            value.Any(character =>
                character is not (>= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_')))
        {
            throw new ArgumentException(
                "HIP protocol nonces must use canonical unpadded base64url.",
                parameterName);
        }

        var remainder = value.Length % 4;
        if (remainder == 1)
        {
            throw new ArgumentException(
                "HIP protocol nonces must use canonical unpadded base64url.",
                parameterName);
        }

        byte[] decoded;
        try
        {
            var base64 = value.Replace('-', '+').Replace('_', '/');
            if (remainder != 0)
            {
                base64 = base64.PadRight(base64.Length + (4 - remainder), '=');
            }

            decoded = Convert.FromBase64String(base64);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "HIP protocol nonces must use canonical unpadded base64url.",
                parameterName,
                exception);
        }

        if (decoded.Length < minimumBytes || decoded.Length > maximumBytes)
        {
            throw new ArgumentException(
                $"HIP protocol nonces must decode to between {minimumBytes} and {maximumBytes} bytes.",
                parameterName);
        }

        var canonical = Convert.ToBase64String(decoded)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        if (!string.Equals(canonical, value, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "HIP protocol nonces must use canonical unpadded base64url.",
                parameterName);
        }

        return value;
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
