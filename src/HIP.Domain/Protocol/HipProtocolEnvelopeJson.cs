using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HIP.Domain.Protocol;

/// <summary>
/// Strict versioned wire serialization for HIP envelopes. RFC 8785 signing canonicalization is a separate protocol service.
/// </summary>
public static class HipProtocolEnvelopeJson
{
    public const int MaximumEnvelopeBytes = 65_536;
    private const int MaximumJsonDepth = 16;
    private static readonly JsonSerializerOptions SerializerOptions = CreateOptions();

    public static string Serialize(HipProtocolEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var json = JsonSerializer.SerializeToUtf8Bytes(envelope, SerializerOptions);
        if (json.Length > MaximumEnvelopeBytes)
        {
            throw new JsonException($"HIP protocol envelopes cannot exceed {MaximumEnvelopeBytes} UTF-8 bytes.");
        }

        return Encoding.UTF8.GetString(json);
    }

    public static HipProtocolEnvelope Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (Encoding.UTF8.GetByteCount(json) > MaximumEnvelopeBytes)
        {
            throw new JsonException($"HIP protocol envelopes cannot exceed {MaximumEnvelopeBytes} UTF-8 bytes.");
        }

        return Deserialize(Encoding.UTF8.GetBytes(json));
    }

    public static HipProtocolEnvelope Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.IsEmpty || utf8Json.Length > MaximumEnvelopeBytes)
        {
            throw new JsonException($"HIP protocol envelopes must contain between 1 and {MaximumEnvelopeBytes} UTF-8 bytes.");
        }

        ValidateJsonStructure(utf8Json);
        try
        {
            return JsonSerializer.Deserialize<HipProtocolEnvelope>(utf8Json, SerializerOptions)
                ?? throw new JsonException("HIP protocol envelope cannot be null.");
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            throw new JsonException("HIP protocol envelope contains an invalid value.", exception);
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
        options.Converters.Add(new HipProtocolClaimsJsonConverter());
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
        public override HipProtocolVersion Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
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

        public override void Write(Utf8JsonWriter writer, HipProtocolVersion value, JsonSerializerOptions options)
        {
            if (!value.IsSupported)
            {
                throw new JsonException($"HIP protocol version '{value}' is unsupported.");
            }

            writer.WriteStringValue(value.Value);
        }
    }

    private sealed class HipProtocolClaimsJsonConverter : JsonConverter<HipProtocolClaims>
    {
        public override HipProtocolClaims Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException("HIP protocol claims must be a JSON object.");
            }

            var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    return new HipProtocolClaims(values);
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException("HIP protocol claim name expected.");
                }

                var name = reader.GetString()!;
                if (!reader.Read())
                {
                    throw new JsonException("HIP protocol claim value expected.");
                }

                using var document = JsonDocument.ParseValue(ref reader);
                if (!values.TryAdd(name, document.RootElement.Clone()))
                {
                    throw new JsonException($"HIP protocol claim '{name}' is duplicated.");
                }
            }

            throw new JsonException("HIP protocol claims object is incomplete.");
        }

        public override void Write(Utf8JsonWriter writer, HipProtocolClaims value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            foreach (var claim in value.Values)
            {
                writer.WritePropertyName(claim.Key);
                claim.Value.WriteTo(writer);
            }
            writer.WriteEndObject();
        }
    }

    private sealed class HipProtocolTimestampJsonConverter : JsonConverter<DateTimeOffset>
    {
        private const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
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

        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        {
            var timestamp = HipProtocolValidation.RequiredUtcTimestamp(value, nameof(value));
            writer.WriteStringValue(timestamp.ToString(TimestampFormat, CultureInfo.InvariantCulture));
        }
    }
}
