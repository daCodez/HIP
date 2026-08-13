namespace HIP.Domain.Devices;

/// <summary>Identifies the bounded HIP client family associated with a device.</summary>
public enum DevicePlatformType
{
    /// <summary>A HIP browser extension.</summary>
    BrowserExtension = 0,

    /// <summary>A HIP Second Life heads-up display.</summary>
    SecondLifeHud = 1,

    /// <summary>Another HIP client family not represented by a dedicated value.</summary>
    Other = 2
}
