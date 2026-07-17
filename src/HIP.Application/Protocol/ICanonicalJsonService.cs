namespace HIP.Application.Protocol;

/// <summary>
/// Produces the deterministic UTF-8 representation of JSON required by HIP protocol operations.
/// </summary>
public interface ICanonicalJsonService
{
    /// <summary>
    /// Canonicalizes one bounded I-JSON value according to RFC 8785.
    /// </summary>
    /// <param name="utf8Json">The complete JSON value encoded as UTF-8.</param>
    /// <returns>A new byte array containing canonical UTF-8 JSON.</returns>
    /// <exception cref="System.Text.Json.JsonException">
    /// The input is malformed, non-I-JSON, outside protocol limits, or cannot be represented canonically.
    /// </exception>
    byte[] Canonicalize(ReadOnlySpan<byte> utf8Json);
}
