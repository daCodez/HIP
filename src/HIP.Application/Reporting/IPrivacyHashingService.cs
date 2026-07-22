namespace HIP.Application.Reporting;

public interface IPrivacyHashingService
{
    /// <summary>Computes the privacy hash written by new records.</summary>
    string Hash(string value);

    /// <summary>
    /// Computes the current hash followed by any bounded legacy-key hashes supported for rotation reads.
    /// Implementations that do not support rotation remain source compatible and return only the current hash.
    /// </summary>
    IReadOnlyList<string> HashCandidates(string value) => [Hash(value)];
}
