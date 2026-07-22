namespace HIP.Infrastructure.Persistence;

/// <summary>
/// One authenticated encrypted record returned by a bounded record-store page.
/// </summary>
/// <typeparam name="T">Decrypted payload type.</typeparam>
/// <param name="Id">Exact persisted record identifier.</param>
/// <param name="Record">Authenticated decrypted payload.</param>
/// <param name="AggregateVersion">Database compare-and-swap version stored beside the payload.</param>
public sealed record HipEncryptedRecordPageItem<T>(
    string Id,
    T Record,
    long AggregateVersion);

/// <summary>
/// A bounded page from one exact encrypted-record partition. The continuation value is the last
/// returned database identifier and must be wrapped by an owner-bound application cursor before
/// it crosses a persistence boundary.
/// </summary>
/// <typeparam name="T">Decrypted payload type.</typeparam>
/// <param name="Items">At most the requested number of authenticated records.</param>
/// <param name="NextCursor">Exact last-returned identifier when another row exists.</param>
public sealed record HipEncryptedRecordPage<T>(
    IReadOnlyList<HipEncryptedRecordPageItem<T>> Items,
    string? NextCursor);
