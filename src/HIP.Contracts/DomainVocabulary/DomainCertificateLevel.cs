namespace HIP.Domain.Certificates;

/// <summary>Public assurance level represented by a HIP Domain Trust Certificate.</summary>
public enum DomainCertificateLevel
{
    /// <summary>Domain control has been registered with HIP.</summary>
    Registered = 0,

    /// <summary>The domain has passed HIP's published verification requirements.</summary>
    Verified = 1,

    /// <summary>The verified domain is enrolled in continuous HIP monitoring.</summary>
    Monitored = 2,

    /// <summary>The domain has passed HIP's published advanced certification requirements.</summary>
    Certified = 3
}
