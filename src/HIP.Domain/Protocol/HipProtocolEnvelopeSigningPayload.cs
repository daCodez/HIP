using System.Text.Json;

namespace HIP.Domain.Protocol;

/// <summary>
/// Produces the version-one signing object by removing only the signature value.
/// The returned JSON must still be RFC 8785-canonicalized before hashing or signing.
/// </summary>
public static class HipProtocolEnvelopeSigningPayload
{
    /// <summary>Serializes every signed envelope field except <c>signature.value</c>.</summary>
    public static byte[] Create(HipProtocolEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        using var document = JsonDocument.Parse(HipProtocolEnvelopeJson.Serialize(envelope));
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                writer.WritePropertyName(property.Name);
                if (!string.Equals(property.Name, "signature", StringComparison.Ordinal))
                {
                    property.Value.WriteTo(writer);
                    continue;
                }

                writer.WriteStartObject();
                foreach (var signatureProperty in property.Value.EnumerateObject())
                {
                    if (!string.Equals(signatureProperty.Name, "value", StringComparison.Ordinal))
                    {
                        signatureProperty.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}
