using System.Buffers;
using System.Text;
using System.Text.Json;
using HIP.Protocol.Contracts;

namespace HIP.Protocol.Canonicalization;

public interface IHipCanonicalSerializer
{
    string CanonicalizeEnvelope(HipMessageEnvelope envelope);
    string CanonicalizeReceipt(HipTrustReceipt receipt);
}

public interface IHipCanonicalBufferSerializer
{
    void WriteCanonicalEnvelope(HipMessageEnvelope envelope, IBufferWriter<byte> buffer);
    void WriteCanonicalReceipt(HipTrustReceipt receipt, IBufferWriter<byte> buffer);
}

/// <summary>
/// HIP v1 canonical serializer.
/// Rules:
/// - UTF-8
/// - deterministic fixed field order
/// - lowercase field names
/// - UTC timestamp in round-trip format
/// - omit null fields
/// - no insignificant whitespace
/// </summary>
public sealed class HipCanonicalSerializer : IHipCanonicalSerializer, IHipCanonicalBufferSerializer
{
    public string CanonicalizeEnvelope(HipMessageEnvelope envelope)
        => SerializeToUtf8String(buffer => WriteCanonicalEnvelope(envelope, buffer));

    public string CanonicalizeReceipt(HipTrustReceipt receipt)
        => SerializeToUtf8String(buffer => WriteCanonicalReceipt(receipt, buffer));

    public void WriteCanonicalEnvelope(HipMessageEnvelope envelope, IBufferWriter<byte> buffer)
    {
        if (string.Equals(envelope.HipVersion, HipProtocolVersions.V1Binary, StringComparison.OrdinalIgnoreCase))
        {
            WriteBinaryEnvelope(envelope, buffer);
            return;
        }

        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("hipversion", envelope.HipVersion);
        writer.WriteString("messagetype", envelope.MessageType);
        writer.WriteString("senderhipid", envelope.SenderHipId);
        if (!string.IsNullOrWhiteSpace(envelope.ReceiverHipId)) writer.WriteString("receiverhipid", envelope.ReceiverHipId);
        WriteUtcTimestamp(writer, "timestamputc", envelope.TimestampUtc);
        writer.WriteString("nonce", envelope.Nonce);
        writer.WriteString("payloadhash", envelope.PayloadHash);
        writer.WriteString("correlationid", envelope.CorrelationId);
        if (!string.IsNullOrWhiteSpace(envelope.DeviceId)) writer.WriteString("deviceid", envelope.DeviceId);

        if (envelope.TrustClaims is { Count: > 0 })
        {
            writer.WritePropertyName("trustclaims");
            writer.WriteStartArray();
            foreach (var claim in envelope.TrustClaims)
            {
                writer.WriteStartObject();
                writer.WriteString("claimtype", claim.ClaimType);
                writer.WriteString("claimvalue", claim.ClaimValue);
                writer.WriteString("source", claim.Source);
                WriteUtcTimestamp(writer, "timestamputc", claim.TimestampUtc);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }

        if (envelope.Extensions is { Count: > 0 })
        {
            writer.WritePropertyName("extensions");
            writer.WriteStartObject();
            WriteOrderedExtensions(writer, envelope.Extensions);
            writer.WriteEndObject();
        }

        writer.WriteEndObject();
        writer.Flush();
    }

    public void WriteCanonicalReceipt(HipTrustReceipt receipt, IBufferWriter<byte> buffer)
    {
        if (string.Equals(receipt.HipVersion, HipProtocolVersions.V1Binary, StringComparison.OrdinalIgnoreCase))
        {
            WriteBinaryReceipt(receipt, buffer);
            return;
        }

        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString("receiptid", receipt.ReceiptId);
        writer.WriteString("hipversion", receipt.HipVersion);
        writer.WriteString("interactiontype", receipt.InteractionType);
        writer.WriteString("senderhipid", receipt.SenderHipId);
        if (!string.IsNullOrWhiteSpace(receipt.ReceiverHipId)) writer.WriteString("receiverhipid", receipt.ReceiverHipId);
        WriteUtcTimestamp(writer, "timestamputc", receipt.TimestampUtc);
        writer.WriteString("messagehash", receipt.MessageHash);
        if (!string.IsNullOrWhiteSpace(receipt.DeviceId)) writer.WriteString("deviceid", receipt.DeviceId);

        writer.WritePropertyName("checks");
        writer.WriteStartArray();
        foreach (var c in receipt.Checks) writer.WriteStringValue(c);
        writer.WriteEndArray();

        writer.WriteString("decision", receipt.Decision switch
        {
            HipDecision.Allow => "Allow",
            HipDecision.Challenge => "Challenge",
            HipDecision.Warn => "Warn",
            HipDecision.RateLimit => "RateLimit",
            HipDecision.Quarantine => "Quarantine",
            HipDecision.Block => "Block",
            _ => receipt.Decision.ToString()
        });

        writer.WritePropertyName("appliedpolicyids");
        writer.WriteStartArray();
        foreach (var p in receipt.AppliedPolicyIds) writer.WriteStringValue(p);
        writer.WriteEndArray();

        if (receipt.ReputationSnapshot.HasValue) writer.WriteNumber("reputationsnapshot", receipt.ReputationSnapshot.Value);

        writer.WriteEndObject();
        writer.Flush();
    }

    private static string SerializeToUtf8String(Action<IBufferWriter<byte>> write)
    {
        var buffer = new ArrayBufferWriter<byte>(512);
        write(buffer);
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteUtcTimestamp(Utf8JsonWriter writer, string propertyName, DateTimeOffset value)
    {
        Span<char> timestamp = stackalloc char[33];
        if (value.UtcDateTime.TryFormat(timestamp, out var written, "O"))
        {
            writer.WriteString(propertyName, timestamp[..written]);
            return;
        }

        writer.WriteString(propertyName, value.UtcDateTime.ToString("O"));
    }

    private static void WriteBinaryEnvelope(HipMessageEnvelope envelope, IBufferWriter<byte> buffer)
    {
        WriteByte(buffer, 0x01); // format marker
        WriteString(buffer, envelope.HipVersion);
        WriteString(buffer, envelope.MessageType);
        WriteString(buffer, envelope.SenderHipId);
        WriteNullableString(buffer, envelope.ReceiverHipId);
        WriteInt64(buffer, envelope.TimestampUtc.ToUnixTimeMilliseconds());
        WriteString(buffer, envelope.Nonce);
        WriteString(buffer, envelope.PayloadHash);
        WriteString(buffer, envelope.CorrelationId);
        WriteNullableString(buffer, envelope.DeviceId);

        var claims = envelope.TrustClaims;
        WriteInt32(buffer, claims?.Count ?? 0);
        if (claims is { Count: > 0 })
        {
            foreach (var claim in claims)
            {
                WriteString(buffer, claim.ClaimType);
                WriteString(buffer, claim.ClaimValue);
                WriteString(buffer, claim.Source);
                WriteInt64(buffer, claim.TimestampUtc.ToUnixTimeMilliseconds());
            }
        }

        WriteBinaryExtensions(buffer, envelope.Extensions);
    }

    private static void WriteBinaryReceipt(HipTrustReceipt receipt, IBufferWriter<byte> buffer)
    {
        WriteByte(buffer, 0x02); // format marker
        WriteString(buffer, receipt.HipVersion);
        WriteString(buffer, receipt.ReceiptId);
        WriteString(buffer, receipt.InteractionType);
        WriteString(buffer, receipt.SenderHipId);
        WriteNullableString(buffer, receipt.ReceiverHipId);
        WriteInt64(buffer, receipt.TimestampUtc.ToUnixTimeMilliseconds());
        WriteString(buffer, receipt.MessageHash);
        WriteNullableString(buffer, receipt.DeviceId);

        WriteInt32(buffer, receipt.Checks.Count);
        foreach (var c in receipt.Checks) WriteString(buffer, c);

        WriteString(buffer, receipt.Decision.ToString());
        WriteInt32(buffer, receipt.AppliedPolicyIds.Count);
        foreach (var p in receipt.AppliedPolicyIds) WriteString(buffer, p);

        if (receipt.ReputationSnapshot.HasValue)
        {
            WriteByte(buffer, 1);
            WriteInt32(buffer, receipt.ReputationSnapshot.Value);
        }
        else
        {
            WriteByte(buffer, 0);
        }
    }

    private static void WriteBinaryExtensions(IBufferWriter<byte> buffer, IReadOnlyDictionary<string, string>? extensions)
    {
        if (extensions is not { Count: > 0 })
        {
            WriteInt32(buffer, 0);
            return;
        }

        var count = extensions.Count;
        var rented = ArrayPool<string>.Shared.Rent(count);
        try
        {
            var i = 0;
            foreach (var key in extensions.Keys)
            {
                rented[i++] = key;
            }

            Array.Sort(rented, 0, count, StringComparer.Ordinal);
            WriteInt32(buffer, count);
            for (i = 0; i < count; i++)
            {
                var key = rented[i];
                WriteString(buffer, ToLowerIfNeeded(key));
                WriteString(buffer, extensions[key]);
            }
        }
        finally
        {
            Array.Clear(rented, 0, count);
            ArrayPool<string>.Shared.Return(rented);
        }
    }

    private static void WriteByte(IBufferWriter<byte> buffer, byte value)
    {
        var span = buffer.GetSpan(1);
        span[0] = value;
        buffer.Advance(1);
    }

    private static void WriteInt32(IBufferWriter<byte> buffer, int value)
    {
        var span = buffer.GetSpan(4);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(span, value);
        buffer.Advance(4);
    }

    private static void WriteInt64(IBufferWriter<byte> buffer, long value)
    {
        var span = buffer.GetSpan(8);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(span, value);
        buffer.Advance(8);
    }

    private static void WriteNullableString(IBufferWriter<byte> buffer, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            WriteInt32(buffer, -1);
            return;
        }

        WriteString(buffer, value);
    }

    private static void WriteString(IBufferWriter<byte> buffer, string value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        WriteInt32(buffer, byteCount);
        var span = buffer.GetSpan(byteCount);
        var written = Encoding.UTF8.GetBytes(value.AsSpan(), span);
        buffer.Advance(written);
    }

    private static void WriteOrderedExtensions(Utf8JsonWriter writer, IReadOnlyDictionary<string, string> extensions)
    {
        var count = extensions.Count;
        var rented = ArrayPool<string>.Shared.Rent(count);
        try
        {
            var i = 0;
            foreach (var key in extensions.Keys)
            {
                rented[i++] = key;
            }

            Array.Sort(rented, 0, count, StringComparer.Ordinal);

            for (i = 0; i < count; i++)
            {
                var key = rented[i];
                writer.WriteString(ToLowerIfNeeded(key), extensions[key]);
            }
        }
        finally
        {
            Array.Clear(rented, 0, count);
            ArrayPool<string>.Shared.Return(rented);
        }
    }

    private static string ToLowerIfNeeded(string key)
    {
        for (var i = 0; i < key.Length; i++)
        {
            if (char.IsUpper(key[i]))
            {
                return key.ToLowerInvariant();
            }
        }

        return key;
    }
}

public interface IHipPayloadHasher
{
    string ComputePayloadHash(string payload);
}

public sealed class Sha256PayloadHasher : IHipPayloadHasher
{
    public string ComputePayloadHash(string payload)
    {
        var bytes = Encoding.UTF8.GetBytes(payload ?? string.Empty);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
