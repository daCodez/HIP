namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for issuing Jarvis access and refresh tokens.
/// </summary>
/// <param name="IdentityId">Identity receiving the token set.</param>
/// <param name="Audience">Audience claim to bind into issued tokens.</param>
/// <param name="DeviceId">Optional device id binding for token replay controls.</param>
public sealed record JarvisTokenIssueRequestDto(string IdentityId, string Audience, string? DeviceId = null);
