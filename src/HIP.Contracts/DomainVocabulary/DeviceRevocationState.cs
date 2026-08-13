namespace HIP.Domain.Devices;

/// <summary>Describes whether a registered device remains active or has been revoked.</summary>
public enum DeviceRevocationState
{
    /// <summary>The device registration remains active.</summary>
    Active = 0,

    /// <summary>The device registration has been revoked.</summary>
    Revoked = 1
}
