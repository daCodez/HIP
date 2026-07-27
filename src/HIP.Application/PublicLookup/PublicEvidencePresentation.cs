namespace HIP.Application.PublicLookup;

/// <summary>Stable public values that separate evidence sufficiency from identity and risk scoring.</summary>
public static class PublicEvidencePresentation
{
    public const string ScoreAvailable = "Available";
    public const string ScoreWithheldInsufficientEvidence = "WithheldInsufficientEvidence";

    public const string CoverageInsufficient = "Insufficient";
    public const string CoverageSufficient = "Sufficient";

    public const string ConfidenceNone = "None";
    public const string ConfidenceMedium = "Medium";
    public const string ConfidenceHigh = "High";

    /// <summary>Normalizes the public identity lifecycle without hiding detailed revoked or suspended state.</summary>
    public static string IdentityStatus(string verificationStatus) => verificationStatus switch
    {
        "Verified" => "Verified",
        "Pending" => "Pending",
        _ => "Unverified"
    };

    /// <summary>Returns the compatibility score only when HIP has explicitly authorized numeric presentation.</summary>
    public static int? DisplayScore(string scorePresentation, int compatibilityScore) =>
        string.Equals(scorePresentation, ScoreAvailable, StringComparison.Ordinal)
            ? compatibilityScore
            : null;
}
