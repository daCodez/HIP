namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Describes an encrypted record that must commit in the same transaction as a versioned HIP aggregate.
/// </summary>
/// <typeparam name="T">Related record payload type.</typeparam>
/// <param name="Partition">Logical encrypted-record partition.</param>
/// <param name="Id">Stable record identifier.</param>
/// <param name="Value">Record payload.</param>
public sealed record HipRelatedRecordWrite<T>(string Partition, string Id, T Value);
