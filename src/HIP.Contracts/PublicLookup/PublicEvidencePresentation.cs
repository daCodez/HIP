namespace HIP.Application.PublicLookup;

/// <summary>Stable public values that separate evidence sufficiency from identity and risk scoring.</summary>
public static class PublicEvidencePresentation
{
    /// <summary>A numeric score may be presented to the caller.</summary>
    public const string ScoreAvailable = "Available";

    /// <summary>A numeric score is withheld because authenticated evidence is insufficient.</summary>
    public const string ScoreWithheldInsufficientEvidence = "WithheldInsufficientEvidence";

    /// <summary>The available authenticated evidence does not cover enough signals for scoring.</summary>
    public const string CoverageInsufficient = "Insufficient";

    /// <summary>The available authenticated evidence covers enough signals for scoring.</summary>
    public const string CoverageSufficient = "Sufficient";

    /// <summary>No confidence can be assigned to the available authenticated evidence.</summary>
    public const string ConfidenceNone = "None";

    /// <summary>The available authenticated evidence supports medium confidence.</summary>
    public const string ConfidenceMedium = "Medium";

    /// <summary>The available authenticated evidence supports high confidence.</summary>
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
