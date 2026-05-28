using FluentValidation.Results;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IRuleJsonService
{
    string ToJson(TrustRule rule);

    bool TryParse(string json, out TrustRule? rule, out IReadOnlyCollection<string> errors);

    ValidationResult Validate(TrustRule rule);
}
