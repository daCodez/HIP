using HIP.Web.Marketing.Models;

namespace HIP.Web.Marketing.Data;

/// <summary>
/// Illustrative content for the marketing site. Example results are clearly
/// labelled as such in the UI — nothing here is a live scan.
/// </summary>
public static class SiteData
{
    public static readonly List<string> Signals = new()
    {
        "Secure connection",
        "Valid certificate",
        "Who owns the domain",
        "Past reputation",
        "How the page behaves",
        "Pressure tactics in the wording",
        "Independent security checks"
    };

    public static readonly List<Finding> Findings = new()
    {
        new("https.enforced", "Connection is encrypted", "Your traffic to this site is private", "Connection", "Safe", Tone.Ok, "+12",
            "HSTS present, max-age 31536000 \u00b7 TLS 1.3 \u00b7 HTTP redirects to HTTPS"),
        new("cert.valid", "Security certificate is valid", "Issued by a trusted authority, renews in 74 days", "Certificate", "Safe", Tone.Ok, "+8",
            "x509 chain validated to a trusted root \u00b7 notAfter in 74d \u00b7 SAN covers apex and www"),
        new("owner.txt", "Domain ownership verified", "The owner proved they control this domain", "Ownership", "Verified", Tone.Ok, "+6",
            "_hip TXT record resolves and matches the account binding"),
        new("mail.auth_partial", "Weak email protection", "Someone could send email pretending to be this domain", "Email", "Needs work", Tone.Warn, "\u22126",
            "SPF present, DKIM present, DMARC p=none \u00b7 no enforcement policy"),
        new("third.party_new", "A new third-party script appeared", "Worth checking that you added it on purpose", "Page behaviour", "Monitor", Tone.Warn, "\u22122",
            "1 new script origin since previous scan \u00b7 no SRI hash"),
        new("provider.gsb", "No harmful behaviour found", "Clean across three independent security services", "Reputation", "Safe", Tone.Ok, "+4",
            "Safe Browsing, VirusTotal and SSL Labs all report no listing")
    };

    /// <summary>Both pages in every pair are fictional.</summary>
    public static readonly List<SpotRound> Rounds = new()
    {
        new SpotRound("Northgate Bank", "Sign in to online banking", "b", new List<SpotOption>
        {
            new("a", "northgate-bank.com/signin", true, null, 91, "Trusted", Tone.Ok, new List<SpotSignal>
            {
                new(Tone.Ok, "Connection is encrypted", "Valid certificate, issued to Northgate Bank"),
                new(Tone.Ok, "Domain ownership verified", "Registered 14 years ago, owner proven"),
                new(Tone.Ok, "No harmful behaviour found", "Clean across three independent services")
            }),
            new("b", "northgate-bank.secure-verify-login.com", false,
                "Your account will be locked in 24 hours. Verify now to avoid suspension.", 19, "High Risk", Tone.Risk, new List<SpotSignal>
            {
                new(Tone.Risk, "Password sent unencrypted", "The sign-in form posts over plain HTTP"),
                new(Tone.Risk, "Brand name is not the domain", "The real domain here is secure-verify-login.com"),
                new(Tone.Warn, "Pressure tactics in the wording", "A deadline is used to rush your decision")
            })
        }),
        new SpotRound("Parcelo Delivery", "Track your delivery", "a", new List<SpotOption>
        {
            new("a", "parcelo-tracking.net/reschedule", false,
                "Delivery failed. Pay the \u00a31.79 redelivery fee within 12 hours.", 27, "High Risk", Tone.Risk, new List<SpotSignal>
            {
                new(Tone.Risk, "Domain is four days old", "Registered days before this page appeared"),
                new(Tone.Risk, "Payment form on an unverified domain", "Card details would go to an unknown operator"),
                new(Tone.Warn, "Pressure tactics in the wording", "A small fee and a short deadline, together")
            }),
            new("b", "parcelo.com/track", true, null, 88, "Trusted", Tone.Ok, new List<SpotSignal>
            {
                new(Tone.Ok, "Connection is encrypted", "Valid certificate, issued to Parcelo Ltd"),
                new(Tone.Ok, "Domain ownership verified", "Matches the company behind the brand"),
                new(Tone.Warn, "Weak email protection", "One finding worth resolving, not a risk to you")
            })
        })
    };

    public static readonly List<Faq> Faqs = new()
    {
        new("Is a high HIP score a guarantee that a site is safe?",
            "No. A score describes what HIP checked on a specific date and what it found. It is strong evidence, not a promise — HIP cannot see everything, and no system prevents every threat. The date and the checked-signal list are always shown next to the score for exactly this reason."),
        new("How is this different from a security vendor's rating?",
            "The rules are open. You can read every detection, see its weight, argue with it in public, and propose a change. Nothing about a HIP score depends on trusting a company you cannot inspect."),
        new("What happens if HIP gets my site wrong?",
            "Contest it. Findings marked appealable can be appealed with context, a human reviews the same evidence you see, and the outcome is either an adjustment to your result or a fix to the rule for everyone. Appeals and their outcomes are recorded."),
        new("Do I have to install anything on my website?",
            "No. Scanning needs nothing from you. Verification asks you to publish one DNS TXT record. The optional badge is a single link and image — no tracking scripts."),
        new("What data does HIP keep about visitors?",
            "HIP is built to check content, not people. It records what it observed about a domain or page and when. The design goal for future work on links, email and chat is the same: no storage of private conversations and no unnecessary personal data."),
        new("Which parts are not built yet?",
            "The HIP-aware DNS service and the extension of the trust layer to email, chat, images and files are planned, not shipped. Anything on this site marked DESIGN or RESEARCH is a direction — the roadmap in the repository is the honest source.")
    };
}
