namespace HIP.Domain.Identity;

/// <summary>Identifies the interoperable kind of content represented by a HIP document.</summary>
public enum HipContentType
{
    /// <summary>A website as a whole.</summary>
    Website = 0,
    /// <summary>An individual web page.</summary>
    WebPage = 1,
    /// <summary>A file.</summary>
    File = 2,
    /// <summary>An image.</summary>
    Image = 3,
    /// <summary>An application.</summary>
    App = 4,
    /// <summary>An application programming interface response.</summary>
    ApiResponse = 5,
    /// <summary>An email message.</summary>
    Email = 6,
    /// <summary>A social-media post.</summary>
    SocialPost = 7,
    /// <summary>A downloadable resource.</summary>
    Download = 8,
    /// <summary>A rule-evaluation result.</summary>
    RuleResult = 9
}
