namespace HIP.Domain.Identity;

/// <summary>Identifies a public method by which control of a website or domain can be demonstrated.</summary>
public enum VerificationMethod
{
    DnsTxt,
    WellKnownHipJson,
    HtmlFile,
    MetaTag
}
