namespace HIP.Web.Marketing.Data;

/// <summary>
/// One source for the public methodology widgets. Runtime scan results remain
/// authoritative and carry their own immutable rule version.
/// </summary>
public static class PublishedRuleCatalog
{
    public const string CurrentVersion = "public-methodology/2";
    public const string PreviousVersion = "public-methodology/1";
    public const int Baseline = 70;
    public const int BadgeThreshold = 85;

    public sealed record Rule(
        string Key,
        string Id,
        string Label,
        int OnWeight,
        int OffWeight,
        string OnReason,
        string OffReason,
        bool Required = false);

    public sealed record Change(string Id, int Before, int After, string Reason);

    public static IReadOnlyList<Rule> CurrentRules { get; } =
    [
        new("https", "https.enforced", "HTTPS enforced with HSTS", 12, -18, "HTTPS enforced, HSTS present", "Site does not force a secure connection", true),
        new("cert", "cert.valid", "Certificate valid and trusted", 8, -14, "Certificate valid, trusted issuer", "Certificate expired or untrusted", true),
        new("owner", "owner.txt", "Domain ownership verified", 6, 0, "Ownership verified via DNS", "", true),
        new("mail", "mail.auth", "Mail authentication complete", 6, -6, "SPF, DKIM and DMARC enforced", "Mail authentication incomplete"),
        new("providers", "provider.clean", "No provider listings", 4, -25, "No listings across providers", "Listed by an external security provider"),
        new("scripts", "third.party_known", "All third-party scripts known", 2, -2, "No unexpected third-party scripts", "A new third-party script appeared"),
        new("form", "form.credentials_secure", "Credentials submitted securely", 0, -35, "", "A password field submits over an unencrypted connection", true),
        new("age", "domain.established", "Domain established over a year", 4, -8, "Established domain history", "Domain registered very recently")
    ];

    public static IReadOnlyList<Change> Changes { get; } =
    [
        new("mail.auth", -10, -6, "Apply the full penalty only when the domain actually sends mail."),
        new("form.credentials_secure", -25, -35, "Give insecure credential submission the strongest required-check penalty."),
        new("domain.established", -12, -8, "Treat limited history as uncertainty, not proof of bad intent.")
    ];
}
