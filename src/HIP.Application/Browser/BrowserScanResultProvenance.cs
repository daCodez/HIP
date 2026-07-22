namespace HIP.Application.Browser;

/// <summary>
/// Defines server-owned provenance values for stored browser scan summaries.
/// </summary>
public static class BrowserScanResultProvenance
{
    /// <summary>Metadata key that records whether HIP may use a scan as authoritative evidence.</summary>
    public const string MetadataKey = "submissionTrust";

    /// <summary>Value assigned only by HIP-owned evaluation paths.</summary>
    public const string ServerAuthoritative = "server-authoritative";

    /// <summary>Value assigned to anonymous or otherwise unattested client submissions.</summary>
    public const string UntrustedClient = "untrusted-client";

    /// <summary>Value assigned after a registered, active device proves request possession.</summary>
    public const string RegisteredDevice = "registered-device";

    /// <summary>Serialized JSON fragment used by typed persistence to select authoritative records.</summary>
    public const string ServerAuthoritativeJsonFragment = "\"submissionTrust\":\"server-authoritative\"";

    /// <summary>
    /// Returns whether a stored scan carries provenance assigned by a HIP-owned evaluation path.
    /// </summary>
    /// <param name="record">Stored scan record.</param>
    /// <returns>True only for an exact server-authoritative marker.</returns>
    public static bool IsServerAuthoritative(BrowserScanResultRecord record) =>
        record.PrivacySafeMetadata.TryGetValue(MetadataKey, out var trust) &&
        trust.Equals(ServerAuthoritative, StringComparison.Ordinal);

    /// <summary>
    /// Returns the normalized server-owned provenance label for a stored scan.
    /// </summary>
    /// <param name="record">Stored scan record.</param>
    /// <returns>The authoritative label only for an exact server marker; all other records are untrusted.</returns>
    public static string GetSubmissionTrust(BrowserScanResultRecord record) =>
        IsServerAuthoritative(record)
            ? ServerAuthoritative
            : record.PrivacySafeMetadata.TryGetValue(MetadataKey, out var trust) &&
              trust.Equals(RegisteredDevice, StringComparison.Ordinal)
                ? RegisteredDevice
                : UntrustedClient;
}
