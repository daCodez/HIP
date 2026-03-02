namespace HIP.ApiService.Application.Contracts;

/// <summary>
/// Request payload for consuming a Jarvis proof token.
/// </summary>
/// <param name="ProofToken">Proof token to consume.</param>
/// <param name="ExpectedAction">Action that the token must authorize.</param>
/// <param name="Audience">Optional expected audience constraint.</param>
/// <param name="DeviceId">Optional expected device binding.</param>
public sealed record JarvisProofTokenConsumeRequestDto(string ProofToken, string ExpectedAction, string? Audience = null, string? DeviceId = null);
