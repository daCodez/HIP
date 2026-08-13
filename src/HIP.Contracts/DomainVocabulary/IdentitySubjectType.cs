namespace HIP.Domain.Identity;

/// <summary>Identifies the interoperable kind of subject described by HIP identity evidence.</summary>
public enum IdentitySubjectType
{
    /// <summary>A person.</summary>
    Person,
    /// <summary>A website.</summary>
    Website,
    /// <summary>An internet domain.</summary>
    Domain,
    /// <summary>An application.</summary>
    App,
    /// <summary>An organization.</summary>
    Organization,
    /// <summary>A device-associated key.</summary>
    DeviceKey,
    /// <summary>An avatar in a virtual world.</summary>
    VirtualWorldAvatar,
    /// <summary>A publisher of content.</summary>
    ContentPublisher
}
