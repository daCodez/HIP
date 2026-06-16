namespace HIP.Application.Identity;

/// <summary>
/// Resolves DNS TXT records for identity verification without exposing DNS client implementation details to the application layer.
/// </summary>
public interface IDnsTxtRecordResolver
{
    /// <summary>
    /// Resolves TXT record values for the supplied DNS name.
    /// </summary>
    /// <param name="recordName">Fully qualified record name such as _hip.example.com.</param>
    /// <param name="cancellationToken">Token used to cancel the DNS lookup.</param>
    /// <returns>Flattened TXT record values.</returns>
    Task<IReadOnlyCollection<string>> ResolveTxtRecordsAsync(string recordName, CancellationToken cancellationToken);
}
