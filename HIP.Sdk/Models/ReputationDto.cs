namespace HIP.Sdk.Models;

public sealed record ReputationDto(string IdentityId, int Score, DateTimeOffset UtcTimestamp);
