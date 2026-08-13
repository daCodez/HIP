namespace HIP.Domain.Identity;

/// <summary>Identifies a public method by which control of a website or domain can be demonstrated.</summary>
public enum VerificationMethod
{
    /// <summary>A DNS TXT record.</summary>
    DnsTxt,
    /// <summary>A HIP document at the standardized well-known path.</summary>
    WellKnownHipJson,
    /// <summary>An HTML verification file.</summary>
    HtmlFile,
    /// <summary>An HTML metadata tag.</summary>
    MetaTag
}
