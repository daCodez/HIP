using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HIP.Application.Devices;

/// <summary>
/// Carries a registered device's proof that it authorized one HTTP request body.
/// </summary>
/// <param name="DeviceId">Opaque registered-device identifier issued by HIP.</param>
/// <param name="Timestamp">Unix timestamp, in seconds, included in the signed input.</param>
/// <param name="Nonce">Client-generated base64url nonce included in the signed input.</param>
/// <param name="BodyDigest">Lowercase SHA-256 digest produced by <see cref="DeviceRequestProofCanonicalizer.BodyDigest{TBody}(TBody)"/>.</param>
/// <param name="Signature">Base64url ES256 signature over the canonical signing input.</param>
public sealed record DeviceRequestProof(
    string DeviceId,
    string Timestamp,
    string Nonce,
    string BodyDigest,
    string Signature);

/// <summary>
/// Produces the version-one digest and signing input required by registered-device clients.
/// </summary>
/// <remarks>
/// This class defines only the interoperable wire recipe. HIP hosts retain timestamp policy,
/// replay protection, device lookup, signature verification, authorization, and failure handling.
/// </remarks>
public static class DeviceRequestProofCanonicalizer
{
    private const string Version = "HIP-DEVICE-REQUEST-V1";
    private const int EncodedEs256SignatureCharacters = 86;
    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Serializes a request body with stable web-JSON naming and returns its lowercase SHA-256 digest.
    /// </summary>
    /// <typeparam name="TBody">Request-body type.</typeparam>
    /// <param name="body">Body to digest. Form values, credentials, and unrelated page content must not be supplied.</param>
    /// <returns>A <c>sha256:</c>-prefixed lowercase hexadecimal digest.</returns>
    public static string BodyDigest<TBody>(TBody body)
    {
        var canonical = CanonicalJson(JsonSerializer.SerializeToElement(body, WebJsonOptions));
        return $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant()}";
    }

    /// <summary>
    /// Builds the exact version-one byte sequence signed by a registered device.
    /// </summary>
    /// <param name="deviceId">Opaque registered-device identifier.</param>
    /// <param name="method">HTTP method. It is normalized to uppercase invariant text.</param>
    /// <param name="path">Request path covered by the signature.</param>
    /// <param name="bodyDigest">Digest returned by <see cref="BodyDigest{TBody}(TBody)"/>.</param>
    /// <param name="timestamp">Unix timestamp text covered by the signature.</param>
    /// <param name="nonce">Base64url nonce covered by the signature.</param>
    /// <returns>UTF-8 version-one signing input.</returns>
    public static byte[] SigningInput(
        string deviceId,
        string method,
        string path,
        string bodyDigest,
        string timestamp,
        string nonce) => Encoding.UTF8.GetBytes(
            $"{Version}\n{deviceId}\n{method.ToUpperInvariant()}\n{path}\n{bodyDigest}\n{timestamp}\n{nonce}");

    /// <summary>
    /// Performs bounded syntactic validation of a request-proof envelope.
    /// </summary>
    /// <param name="proof">Proof envelope to inspect.</param>
    /// <returns><see langword="true"/> when every field has the required public wire shape.</returns>
    /// <remarks>A valid shape is not evidence that HIP accepted the proof or trusts the device.</remarks>
    public static bool IsValidProofShape(DeviceRequestProof? proof) =>
        proof is not null &&
        proof.DeviceId is { Length: > 4 and <= 160 } && proof.DeviceId.StartsWith("dev_", StringComparison.Ordinal) &&
        proof.Timestamp is { Length: >= 10 and <= 64 } &&
        proof.Nonce is { Length: >= 22 and <= 128 } && IsBase64Url(proof.Nonce) &&
        proof.BodyDigest is { Length: 71 } && proof.BodyDigest.StartsWith("sha256:", StringComparison.Ordinal) &&
        proof.BodyDigest[7..].All(static character => char.IsAsciiHexDigit(character) && !char.IsUpper(character)) &&
        proof.Signature is { Length: EncodedEs256SignatureCharacters } && IsBase64Url(proof.Signature);

    private static string CanonicalJson(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => $"{{{string.Join(",", element.EnumerateObject()
            .OrderBy(property => property.Name, StringComparer.Ordinal)
            .Select(property => $"{JsonSerializer.Serialize(property.Name)}:{CanonicalJson(property.Value)}"))}}}",
        JsonValueKind.Array => $"[{string.Join(",", element.EnumerateArray().Select(CanonicalJson))}]",
        JsonValueKind.String => JsonSerializer.Serialize(element.GetString()),
        JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null => element.GetRawText(),
        _ => throw new ArgumentException("Device request proof body is not canonicalizable.")
    };

    private static bool IsBase64Url(string value) => value.All(static character =>
        char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
}
