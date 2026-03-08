using HIP.Protocol.Contracts;

namespace HIP.Protocol.Versioning;

public interface IHipVersionPolicy
{
    bool IsSupported(string? hipVersion);
}

public sealed class HipVersionPolicy : IHipVersionPolicy
{
    private readonly HashSet<string> _supported;

    public HipVersionPolicy(IEnumerable<string>? supported = null)
    {
        _supported = new HashSet<string>(supported ?? [HipProtocolVersions.V1], StringComparer.OrdinalIgnoreCase);
    }

    public bool IsSupported(string? hipVersion)
        => !string.IsNullOrWhiteSpace(hipVersion) && _supported.Contains(hipVersion);
}
