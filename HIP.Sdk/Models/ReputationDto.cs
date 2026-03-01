namespace HIP.Sdk.Models;

/// <summary>
/// Reputation contract returned by HIP reputation lookup endpoints.
/// </summary>
/// <param name="IdentityId">Identity identifier that this reputation score belongs to.</param>
/// <param name="Score">Current computed reputation score for the identity.</param>
/// <param name="UtcTimestamp">UTC timestamp indicating when the score snapshot was generated.</param>
public sealed record ReputationDto(string IdentityId, int Score, DateTimeOffset UtcTimestamp);
