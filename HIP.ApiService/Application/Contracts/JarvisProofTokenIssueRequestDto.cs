namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for issuing a Jarvis proof token.
/// </summary>
/// <param name="IdentityId">Identity receiving the proof token.</param>
/// <param name="Audience">Audience claim to bind into the token.</param>
/// <param name="DeviceId">Optional device id binding.</param>
/// <param name="Action">Action the proof token authorizes.</param>
/// <param name="TtlSeconds">Optional token lifetime override in seconds.</param>
public sealed record JarvisProofTokenIssueRequestDto(string IdentityId, string Audience, string? DeviceId, string Action, int? TtlSeconds = null);
