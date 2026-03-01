namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Identity payload returned by HIP identity lookup APIs.
/// </summary>
/// <param name="Id">Stable identity identifier.</param>
/// <param name="PublicKeyRef">Reference to the identity's public key material.</param>
public sealed record IdentityDto(string Id, string PublicKeyRef);
