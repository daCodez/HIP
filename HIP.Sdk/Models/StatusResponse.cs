namespace HIP.Sdk.Models;

public sealed record StatusResponse(string ServiceName, string AssemblyVersion, DateTimeOffset UtcTimestamp);
