using HIP.Security.Domain.Threats;

namespace HIP.Security.Application.Abstractions.Mappings;

/// <summary>
/// Anti-corruption seam between HIP.Protocol.Security outcomes and HIP.Security threat taxonomy.
/// </summary>
public interface IProtocolSecurityOutcomeMapper
{
    ThreatType MapToThreatType(string outcomeCode);
}
