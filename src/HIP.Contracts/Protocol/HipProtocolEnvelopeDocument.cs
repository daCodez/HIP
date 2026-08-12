using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HIP.Application.Protocol;

/// <summary>Dependency-free public representation of a HIP protocol envelope.</summary>
public sealed record HipProtocolEnvelopeDocument(
    [property: JsonPropertyName("version"), JsonPropertyOrder(0)] string Version,
    [property: JsonPropertyName("messageId"), JsonPropertyOrder(1)] string MessageId,
    [property: JsonPropertyName("nonce"), JsonPropertyOrder(2)] string Nonce,
    [property: JsonPropertyName("issuer"), JsonPropertyOrder(3)] HipProtocolEnvelopeIssuer Issuer,
    [property: JsonPropertyName("subject"), JsonPropertyOrder(4)] HipProtocolEnvelopeSubject Subject,
    [property: JsonPropertyName("contentDigest"), JsonPropertyOrder(5)] HipProtocolEnvelopeDigest ContentDigest,
    [property: JsonPropertyName("claims"), JsonPropertyOrder(6)] IReadOnlyDictionary<string, JsonElement> Claims,
    [property: JsonPropertyName("signature"), JsonPropertyOrder(7)] HipProtocolEnvelopeSignature Signature,
    [property: JsonPropertyName("issuedAtUtc"), JsonPropertyOrder(8)] DateTimeOffset IssuedAtUtc,
    [property: JsonPropertyName("expiresAtUtc"), JsonPropertyOrder(9)] DateTimeOffset ExpiresAtUtc);

/// <summary>Public issuer identifier carried by a HIP envelope.</summary>
public sealed record HipProtocolEnvelopeIssuer(
    [property: JsonPropertyName("id"), JsonPropertyOrder(0)] string Id);

/// <summary>Public subject metadata using the protocol's text subject type.</summary>
public sealed record HipProtocolEnvelopeSubject(
    [property: JsonPropertyName("type"), JsonPropertyOrder(0)] string Type,
    [property: JsonPropertyName("id"), JsonPropertyOrder(1)] string Id);

/// <summary>Public content digest metadata.</summary>
public sealed record HipProtocolEnvelopeDigest(
    [property: JsonPropertyName("algorithm"), JsonPropertyOrder(0)] string Algorithm,
    [property: JsonPropertyName("value"), JsonPropertyOrder(1)] string Value);

/// <summary>Public origin-and-integrity signature metadata. It makes no safety or reputation assertion.</summary>
public sealed record HipProtocolEnvelopeSignature(
    [property: JsonPropertyName("scope"), JsonPropertyOrder(0)] string Scope,
    [property: JsonPropertyName("keyId"), JsonPropertyOrder(1)] string KeyId,
    [property: JsonPropertyName("algorithm"), JsonPropertyOrder(2)] string Algorithm,
    [property: JsonPropertyName("algorithmFamily"), JsonPropertyOrder(3)] string AlgorithmFamily,
    [property: JsonPropertyName("canonicalization"), JsonPropertyOrder(4)] string Canonicalization,
    [property: JsonPropertyName("value"), JsonPropertyOrder(5)] string Value)
{
    [JsonIgnore]
    public bool EstablishesSafetyOrReputation => false;
}

/// <summary>Strict, bounded JSON codec for the public HIP envelope representation.</summary>
public static class HipProtocolEnvelopeDocumentJson
{
    public const int MaximumEnvelopeBytes = 65_536;
    public const int MaximumClaims = 32;
    public const int MaximumClaimNameLength = 64;
    public const int MaximumClaimValueBytes = 4_096;
    private const int MaximumJsonDepth = 16;
    private const int MaximumClaimValueDepth = 8;
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static string Serialize(HipProtocolEnvelopeDocument envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        Validate(envelope);
        var json = JsonSerializer.SerializeToUtf8Bytes(envelope, Options);
        if (json.Length > MaximumEnvelopeBytes)
        {
            throw new JsonException($"HIP protocol envelopes cannot exceed {MaximumEnvelopeBytes} UTF-8 bytes.");
        }

        return Encoding.UTF8.GetString(json);
    }

    public static HipProtocolEnvelopeDocument Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        var utf8 = Encoding.UTF8.GetBytes(json);
        if (utf8.Length is 0 or > MaximumEnvelopeBytes)
        {
            throw new JsonException($"HIP protocol envelopes must contain between 1 and {MaximumEnvelopeBytes} UTF-8 bytes.");
        }

        RejectDuplicateProperties(utf8);
        var envelope = JsonSerializer.Deserialize<HipProtocolEnvelopeDocument>(utf8, Options)
            ?? throw new JsonException("HIP protocol envelope cannot be null.");
        Validate(envelope);
        return envelope;
    }

    public static HipProtocolEnvelopeDocument Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        if (utf8Json.IsEmpty || utf8Json.Length > MaximumEnvelopeBytes)
        {
            throw new JsonException($"HIP protocol envelopes must contain between 1 and {MaximumEnvelopeBytes} UTF-8 bytes.");
        }

        RejectDuplicateProperties(utf8Json);
        var envelope = JsonSerializer.Deserialize<HipProtocolEnvelopeDocument>(utf8Json, Options)
            ?? throw new JsonException("HIP protocol envelope cannot be null.");
        Validate(envelope);
        return envelope;
    }

    private static void Validate(HipProtocolEnvelopeDocument envelope)
    {
        Required(envelope.Version, nameof(envelope.Version), 8);
        Required(envelope.MessageId, nameof(envelope.MessageId), 128);
        Required(envelope.Nonce, nameof(envelope.Nonce), 86);
        ArgumentNullException.ThrowIfNull(envelope.Issuer);
        ArgumentNullException.ThrowIfNull(envelope.Subject);
        ArgumentNullException.ThrowIfNull(envelope.ContentDigest);
        ArgumentNullException.ThrowIfNull(envelope.Signature);
        ArgumentNullException.ThrowIfNull(envelope.Claims);
        Required(envelope.Issuer.Id, nameof(envelope.Issuer.Id), 256);
        Required(envelope.Subject.Type, nameof(envelope.Subject.Type), 64);
        Required(envelope.Subject.Id, nameof(envelope.Subject.Id), 512);
        Required(envelope.ContentDigest.Algorithm, nameof(envelope.ContentDigest.Algorithm), 32);
        Required(envelope.ContentDigest.Value, nameof(envelope.ContentDigest.Value), 128);
        Required(envelope.Signature.Scope, nameof(envelope.Signature.Scope), 64);
        Required(envelope.Signature.KeyId, nameof(envelope.Signature.KeyId), 128);
        Required(envelope.Signature.Algorithm, nameof(envelope.Signature.Algorithm), 128);
        Required(envelope.Signature.AlgorithmFamily, nameof(envelope.Signature.AlgorithmFamily), 64);
        Required(envelope.Signature.Canonicalization, nameof(envelope.Signature.Canonicalization), 64);
        Required(envelope.Signature.Value, nameof(envelope.Signature.Value), 16_384);
        if (envelope.Claims.Count > MaximumClaims || envelope.ExpiresAtUtc <= envelope.IssuedAtUtc)
        {
            throw new JsonException("HIP protocol envelope claims or validity window are invalid.");
        }

        foreach (var claim in envelope.Claims)
        {
            Required(claim.Key, "claim name", MaximumClaimNameLength);
            if (claim.Value.ValueKind == JsonValueKind.Undefined ||
                Encoding.UTF8.GetByteCount(claim.Value.GetRawText()) > MaximumClaimValueBytes ||
                JsonDepth(claim.Value) > MaximumClaimValueDepth)
            {
                throw new JsonException("HIP protocol claim values exceed the public wire limits.");
            }
        }
    }

    private static void Required(string? value, string name, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new JsonException($"HIP protocol field '{name}' is required and must contain bounded text.");
        }
    }

    private static int JsonDepth(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            return 1 + value.EnumerateObject().Select(property => JsonDepth(property.Value)).DefaultIfEmpty(0).Max();
        }

        if (value.ValueKind == JsonValueKind.Array)
        {
            return 1 + value.EnumerateArray().Select(JsonDepth).DefaultIfEmpty(0).Max();
        }

        return 0;
    }

    private static void RejectDuplicateProperties(ReadOnlySpan<byte> utf8)
    {
        var reader = new Utf8JsonReader(utf8, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = MaximumJsonDepth
        });
        var properties = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) properties.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.PropertyName &&
                     (properties.Count == 0 || !properties.Peek().Add(reader.GetString()!)))
                throw new JsonException("HIP protocol JSON cannot contain duplicate property names.");
            else if (reader.TokenType == JsonTokenType.EndObject) properties.Pop();
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
        options.Converters.Add(new ProtocolTimestampConverter());
        return options;
    }

    private sealed class ProtocolTimestampConverter : JsonConverter<DateTimeOffset>
    {
        private const string Format = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) =>
            reader.TokenType == JsonTokenType.String && DateTimeOffset.TryParseExact(
                reader.GetString(), Format, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value)
                ? value
                : throw new JsonException($"HIP protocol timestamps must use the {Format} UTC format.");

        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        {
            if (value.Offset != TimeSpan.Zero) throw new JsonException("HIP protocol timestamps must be UTC.");
            writer.WriteStringValue(value.ToString(Format, CultureInfo.InvariantCulture));
        }
    }
}
