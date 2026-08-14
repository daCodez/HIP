namespace HIP.Domain.Devices;

/// <summary>Describes only the cryptographic assurance established during device registration.</summary>
public enum DeviceTrustState
{
    /// <summary>The client proved possession of the private key corresponding to its registered public key.</summary>
    ProofOfPossessionVerified = 0
}
