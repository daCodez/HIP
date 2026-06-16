namespace HIP.Application.Identity;

/// <summary>
/// Safe fallback TXT resolver used when infrastructure has not supplied a real DNS client.
/// </summary>
public sealed class NoOpDnsTxtRecordResolver : IDnsTxtRecordResolver
{
    /// <summary>
    /// Returns no TXT records so direct application tests do not perform network I/O accidentally.
    /// </summary>
    /// <param name="recordName">Record name that would be queried by a real resolver.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>An empty TXT record collection.</returns>
    public Task<IReadOnlyCollection<string>> ResolveTxtRecordsAsync(string recordName, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<string>>(Array.Empty<string>());
}
