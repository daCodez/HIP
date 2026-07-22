using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HIP.Domain.Protocol;

/// <summary>
/// Strict versioned wire serialization for HIP trust receipts. RFC 8785 signing canonicalization is a separate protocol service.
/// </summary>
public static class HipTrustReceiptJson
{
    public const int MaximumReceiptBytes = 65_536;
    private const int MaximumJsonDepth = 16;
    private static readonly JsonSerializerOptions SerializerOptions = CreateOptions();

    /// <summary>Serializes a validated HIP trust receipt to its compact wire representation.</summary>
    public static string Serialize(HipTrustReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var json = JsonSerializer.SerializeToUtf8Bytes(receipt, SerializerOptions);
        if (json.Length > MaximumReceiptBytes)
        {
            throw new JsonException($"HIP trust receipts cannot exceed {MaximumReceiptBytes} UTF-8 bytes.");
        }

        return Encoding.UTF8.GetString(json);
    }

    /// <summary>Deserializes and validates a HIP trust receipt from JSON text.</summary>
    public static HipTrustReceipt Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (Encoding.UTF8.GetByteCount(json) > MaximumReceiptBytes)
        {
            throw new JsonException($"HIP trust receipts cannot exceed {MaximumReceiptBytes} UTF-8 bytes.");
        }

        return Deserialize(Encoding.UTF8.GetBytes(json));
    }

    /// <summary>Deserializes and validates a HIP trust receipt from UTF-8 JSON.</summary>
    public static HipTrustReceipt Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.IsEmpty || utf8Json.Length > MaximumReceiptBytes)
        {
            throw new JsonException(
                $"HIP trust receipts must contain between 1 and {MaximumReceiptBytes} UTF-8 bytes.");
        }

        ValidateJsonStructure(utf8Json);
        try
        {
            return JsonSerializer.Deserialize<HipTrustReceipt>(utf8Json, SerializerOptions)
                ?? throw new JsonException("HIP trust receipt cannot be null.");
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            throw new JsonException("HIP trust receipt contains an invalid value.", exception);
        }
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            AllowTrailingCommas = false,
            MaxDepth = MaximumJsonDepth,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = false
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        options.Converters.Add(new HipProtocolVersionJsonConverter());
        options.Converters.Add(new HipProtocolTimestampJsonConverter());
        return options;
    }

    private static void ValidateJsonStructure(ReadOnlySpan<byte> utf8Json)
    {
        var reader = new Utf8JsonReader(utf8Json, new JsonReaderOptions
        {
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
                    if (objectProperties.Count == 0 || !objectProperties.Peek().Add(reader.GetString()!))
                    {
                        throw new JsonException("HIP protocol JSON cannot contain duplicate property names.");
                    }
                    break;
                case JsonTokenType.EndObject:
                    objectProperties.Pop();
                    break;
            }
        }
    }

    private sealed class HipProtocolVersionJsonConverter : JsonConverter<HipProtocolVersion>
    {
        public override HipProtocolVersion Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException("HIP protocol version must be a string.");
            }

            try
            {
                return HipProtocolVersion.Parse(reader.GetString());
            }
            catch (NotSupportedException exception)
            {
                throw new JsonException(exception.Message, exception);
            }
        }

        public override void Write(
            Utf8JsonWriter writer,
            HipProtocolVersion value,
            JsonSerializerOptions options)
        {
            if (!value.IsSupported)
            {
                throw new JsonException($"HIP protocol version '{value}' is unsupported.");
            }

            writer.WriteStringValue(value.Value);
        }
    }

    private sealed class HipProtocolTimestampJsonConverter : JsonConverter<DateTimeOffset>
    {
        private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

        public override DateTimeOffset Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String ||
                !DateTimeOffset.TryParseExact(
                    reader.GetString(),
                    TimestampFormat,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var value))
            {
                throw new JsonException($"HIP protocol timestamps must use the {TimestampFormat} UTC format.");
            }

            return value;
        }

        public override void Write(
            Utf8JsonWriter writer,
            DateTimeOffset value,
            JsonSerializerOptions options)
        {
            var timestamp = HipProtocolValidation.RequiredUtcTimestamp(value, nameof(value));
            writer.WriteStringValue(timestamp.ToString(TimestampFormat, CultureInfo.InvariantCulture));
        }
    }
}
