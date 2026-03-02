namespace HIP.Sdk.Models;

/// <summary>
/// Identity contract returned by HIP identity lookup endpoints.
/// </summary>
/// <param name="Id">Stable identity identifier.</param>
/// <param name="PublicKeyRef">Reference/path/key-id pointer to the public key material for this identity.</param>
public sealed record IdentityDto(string Id, string PublicKeyRef);
