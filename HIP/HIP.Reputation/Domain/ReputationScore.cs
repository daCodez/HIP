namespace HIP.Reputation.Domain;

public sealed record ReputationScore(string IdentityId, int Score, DateTimeOffset CalculatedAtUtc);
