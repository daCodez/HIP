namespace HIP.ApiService.Application.Contracts;

public sealed record ReputationDto(string IdentityId, int Score, DateTimeOffset UtcTimestamp);
