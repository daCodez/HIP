namespace HIP.Domain.Reporting;

/// <summary>Identifies the HIP client surface that submitted a privacy-safe report.</summary>
public enum SourceClient
{
    /// <summary>The source client was not provided or could not be classified.</summary>
    Unknown = 0,

    /// <summary>The browser extension compatibility identifier.</summary>
    BrowserPlugin = 1,

    /// <summary>A Second Life HUD.</summary>
    SecondLifeHud = 2,

    /// <summary>An API client.</summary>
    ApiClient = 3,

    /// <summary>A manually submitted report.</summary>
    ManualReport = 4,

    /// <summary>The public lookup experience.</summary>
    PublicLookup = 5,

    /// <summary>The HIP safety page.</summary>
    SafetyPage = 6,

    /// <summary>The consumer portal.</summary>
    ConsumerPortal = 7,

    /// <summary>The administrative portal.</summary>
    AdminPortal = 8
}
