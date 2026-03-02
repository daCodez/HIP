namespace HIP.Sdk;

/// <summary>
/// Configuration options for the HIP SDK HTTP client registration.
/// </summary>
public sealed class HipSdkOptions
{
    /// <summary>
    /// Base URL for the HIP API service. This should point at the API host/port
    /// that serves routes such as <c>/api/status</c> and <c>/api/identity/*</c>.
    /// </summary>
    public string BaseUrl { get; set; } = "http://127.0.0.1:5101";
}
