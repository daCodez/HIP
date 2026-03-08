namespace HIP.Protocol.Security.Options;

public sealed class HipSecurityOptions
{
    public int AllowedClockSkewSeconds { get; set; } = 300;
    public int ReplayWindowSeconds { get; set; } = 600;
}
