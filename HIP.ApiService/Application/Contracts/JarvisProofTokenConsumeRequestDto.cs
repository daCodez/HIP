namespace HIP.ApiService.Application.Contracts;

public sealed record JarvisProofTokenConsumeRequestDto(string ProofToken, string ExpectedAction, string? Audience = null, string? DeviceId = null);