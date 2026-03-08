using HIP.Security.Application.Abstractions.Mappings;
using HIP.Security.Domain.Threats;

namespace HIP.Security.Infrastructure.Mappings;

public sealed class ProtocolSecurityOutcomeMapper : IProtocolSecurityOutcomeMapper
{
    public ThreatType MapToThreatType(string outcomeCode)
    {
        if (string.IsNullOrWhiteSpace(outcomeCode))
        {
            return ThreatType.Unknown;
        }

        return outcomeCode.Trim().ToLowerInvariant() switch
        {
            "replay" => ThreatType.Replay,
            "credential-attack" => ThreatType.CredentialAttack,
            "injection" => ThreatType.Injection,
            "exfiltration" => ThreatType.Exfiltration,
            "enumeration" => ThreatType.Enumeration,
            "abuse" => ThreatType.Abuse,
            _ => ThreatType.Unknown
        };
    }
}
