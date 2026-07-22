using System.Text.Json;

namespace HIP.Domain.Protocol;

/// <summary>
/// Produces the version-one trust-receipt signing object by removing only the signature value.
/// The returned JSON must still be RFC 8785-canonicalized before hashing or signing.
/// </summary>
public static class HipTrustReceiptSigningPayload
{
    /// <summary>Serializes every signed receipt field except <c>signature.value</c>.</summary>
    public static byte[] Create(HipTrustReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        using var document = JsonDocument.Parse(HipTrustReceiptJson.Serialize(receipt));
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
