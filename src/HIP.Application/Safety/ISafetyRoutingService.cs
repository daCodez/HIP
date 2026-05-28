using HIP.Domain.Safety;

namespace HIP.Application.Safety;

public interface ISafetyRoutingService
{
    SafetyResult CreateUrlSafetyResult(string originalUrl, string? finalDestinationUrl, int domainScore, int? senderScore, IReadOnlyCollection<string> reasons);
}
