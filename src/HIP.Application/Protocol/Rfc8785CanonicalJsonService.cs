using System.Globalization;
using System.Text;
using System.Text.Json;
using HIP.Domain.Protocol;

namespace HIP.Application.Protocol;

/// <summary>
/// Bounded RFC 8785 JSON Canonicalization Scheme implementation for HIP protocol data.
/// </summary>
public sealed class Rfc8785CanonicalJsonService : ICanonicalJsonService
{
    public const int MaximumCanonicalJsonBytes = HipProtocolEnvelopeJson.MaximumEnvelopeBytes;
    public const int MaximumJsonDepth = 16;

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public byte[] Canonicalize(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.IsEmpty || utf8Json.Length > MaximumCanonicalJsonBytes)
        {
            throw new JsonException(
                $"Canonical JSON must contain between 1 and {MaximumCanonicalJsonBytes} UTF-8 bytes.");
        }

        ValidateInput(utf8Json);

        using var document = JsonDocument.Parse(utf8Json.ToArray(), new JsonDocumentOptions
        {
            AllowDuplicateProperties = false,
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = MaximumJsonDepth
        });

        var canonical = new StringBuilder(Math.Min(utf8Json.Length, MaximumCanonicalJsonBytes));
        WriteElement(document.RootElement, canonical);

        var text = canonical.ToString();
        var byteCount = StrictUtf8.GetByteCount(text);
        if (byteCount > MaximumCanonicalJsonBytes)
        {
            throw new JsonException(
                $"Canonical JSON cannot exceed {MaximumCanonicalJsonBytes} UTF-8 bytes.");
        }

        return StrictUtf8.GetBytes(text);
    }

    private static void ValidateInput(ReadOnlySpan<byte> utf8Json)
    {
        try
        {
            var reader = new Utf8JsonReader(utf8Json, new JsonReaderOptions
            {
                AllowMultipleValues = false,
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaximumJsonDepth
            });
            var objectProperties = new Stack<HashSet<string>>();

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        objectProperties.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.PropertyName:
                        var propertyName = reader.GetString()
                            ?? throw new JsonException("Canonical JSON property names cannot be null.");
                        ValidateUnicode(propertyName);
                        if (objectProperties.Count == 0 || !objectProperties.Peek().Add(propertyName))
                        {
                            throw new JsonException("Canonical JSON cannot contain duplicate property names.");
                        }

                        break;
                    case JsonTokenType.String:
                        ValidateUnicode(reader.GetString()
                            ?? throw new JsonException("Canonical JSON strings cannot be null."));
                        break;
                    case JsonTokenType.Number:
                        ValidateNumber(ref reader);
                        break;
                    case JsonTokenType.EndObject:
                        objectProperties.Pop();
                        break;
                }
            }
        }
        catch (JsonException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or DecoderFallbackException or InvalidOperationException)
        {
            throw new JsonException("Canonical JSON contains invalid UTF-8 or Unicode data.", exception);
        }
    }

    private static void ValidateNumber(ref Utf8JsonReader reader)
    {
        if (!reader.TryGetDouble(out var value) || !double.IsFinite(value))
        {
            throw new JsonException("Canonical JSON numbers must be finite IEEE 754 binary64 values.");
        }

        if (BitConverter.DoubleToInt64Bits(value) == long.MinValue)
        {
            // RFC 8785 verified technical erratum 7920 recommends rejecting negative zero before canonicalization.
            throw new JsonException("Canonical JSON cannot contain negative zero.");
        }

        if (value == 0 && ContainsNonZeroSignificandDigit(reader.ValueSpan))
        {
            throw new JsonException("Canonical JSON numbers cannot underflow the IEEE 754 binary64 range.");
        }
    }

    private static bool ContainsNonZeroSignificandDigit(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
        {
            if (item is (byte)'e' or (byte)'E')
            {
                break;
            }

            if (item is >= (byte)'1' and <= (byte)'9')
            {
                return true;
            }
        }

        return false;
    }

    private static void WriteElement(JsonElement element, StringBuilder output)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(element, output);
                break;
            case JsonValueKind.Array:
                WriteArray(element, output);
                break;
            case JsonValueKind.String:
                WriteString(element.GetString()!, output);
                break;
            case JsonValueKind.Number:
                output.Append(FormatNumber(element.GetDouble()));
                break;
            case JsonValueKind.True:
                output.Append("true");
                break;
            case JsonValueKind.False:
                output.Append("false");
                break;
            case JsonValueKind.Null:
                output.Append("null");
                break;
            default:
                throw new JsonException("Canonical JSON contains an unsupported value.");
        }
    }

    private static void WriteObject(JsonElement element, StringBuilder output)
    {
        output.Append('{');
        var first = true;
        foreach (var property in element.EnumerateObject().OrderBy(
                     static property => property.Name,
                     StringComparer.Ordinal))
        {
            if (!first)
            {
                output.Append(',');
            }

            first = false;
            WriteString(property.Name, output);
            output.Append(':');
            WriteElement(property.Value, output);
        }

        output.Append('}');
    }

    private static void WriteArray(JsonElement element, StringBuilder output)
    {
        output.Append('[');
        var first = true;
        foreach (var item in element.EnumerateArray())
        {
            if (!first)
            {
                output.Append(',');
            }

            first = false;
            WriteElement(item, output);
        }

        output.Append(']');
    }

    private static void WriteString(string value, StringBuilder output)
    {
        ValidateUnicode(value);
        output.Append('"');
        foreach (var item in value)
        {
            switch (item)
            {
                case '"':
                    output.Append("\\\"");
                    break;
                case '\\':
                    output.Append("\\\\");
                    break;
                case '\b':
                    output.Append("\\b");
                    break;
                case '\t':
                    output.Append("\\t");
                    break;
                case '\n':
                    output.Append("\\n");
                    break;
                case '\f':
                    output.Append("\\f");
                    break;
                case '\r':
                    output.Append("\\r");
                    break;
                default:
                    if (item <= 0x1f)
                    {
                        output.Append("\\u");
                        output.Append(((int)item).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        output.Append(item);
                    }

                    break;
            }
        }

        output.Append('"');
    }

    private static void ValidateUnicode(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var item = value[index];
            int scalar;
            if (char.IsHighSurrogate(item))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index]))
                {
                    throw new JsonException("Canonical JSON cannot contain lone Unicode surrogates.");
                }

                scalar = char.ConvertToUtf32(item, value[index]);
            }
            else if (char.IsLowSurrogate(item))
            {
                throw new JsonException("Canonical JSON cannot contain lone Unicode surrogates.");
            }
            else
            {
                scalar = item;
            }

            if (IsUnicodeNoncharacter(scalar))
            {
                throw new JsonException("Canonical JSON cannot contain Unicode noncharacters.");
            }
        }
    }

    private static bool IsUnicodeNoncharacter(int scalar) =>
        scalar is >= 0xfdd0 and <= 0xfdef || (scalar & 0xfffe) == 0xfffe;

    private static string FormatNumber(double value)
    {
        if (!double.IsFinite(value))
        {
            throw new JsonException("Canonical JSON numbers must be finite IEEE 754 binary64 values.");
        }

        if (value == 0)
        {
            return "0";
        }

        var roundTrip = value.ToString("R", CultureInfo.InvariantCulture);
        var negative = roundTrip[0] == '-';
        var unsigned = negative ? roundTrip[1..] : roundTrip;
        var exponentIndex = unsigned.IndexOf('E');
        if (exponentIndex < 0)
        {
            exponentIndex = unsigned.IndexOf('e');
        }

        var mantissa = exponentIndex < 0 ? unsigned : unsigned[..exponentIndex];
        var explicitExponent = exponentIndex < 0
            ? 0
            : int.Parse(unsigned[(exponentIndex + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture);
        var decimalPoint = mantissa.IndexOf('.');
        if (decimalPoint < 0)
        {
            decimalPoint = mantissa.Length;
        }

        var allDigits = mantissa.Replace(".", string.Empty, StringComparison.Ordinal);
        var firstSignificant = 0;
        while (firstSignificant < allDigits.Length && allDigits[firstSignificant] == '0')
        {
            firstSignificant++;
        }

        var scientificExponent = decimalPoint + explicitExponent - firstSignificant - 1;
        var significantDigits = allDigits[firstSignificant..].TrimEnd('0');
        var result = new StringBuilder(significantDigits.Length + Math.Abs(scientificExponent) + 8);
        if (negative)
        {
            result.Append('-');
        }

        if (scientificExponent is >= -6 and < 21)
        {
            AppendFixed(significantDigits, scientificExponent, result);
        }
        else
        {
            result.Append(significantDigits[0]);
            if (significantDigits.Length > 1)
            {
                result.Append('.');
                result.Append(significantDigits.AsSpan(1));
            }

            result.Append('e');
            if (scientificExponent >= 0)
            {
                result.Append('+');
            }

            result.Append(scientificExponent.ToString(CultureInfo.InvariantCulture));
        }

        return result.ToString();
    }

    private static void AppendFixed(string digits, int scientificExponent, StringBuilder output)
    {
        var decimalPoint = scientificExponent + 1;
        if (decimalPoint <= 0)
        {
            output.Append("0.");
            output.Append('0', -decimalPoint);
            output.Append(digits);
        }
        else if (decimalPoint >= digits.Length)
        {
            output.Append(digits);
            output.Append('0', decimalPoint - digits.Length);
        }
        else
        {
            output.Append(digits.AsSpan(0, decimalPoint));
            output.Append('.');
            output.Append(digits.AsSpan(decimalPoint));
        }
    }
}
