using System.ComponentModel.DataAnnotations;
using HIP.Security.Api.Contracts.Policies;

namespace HIP.Security.Api.Contracts;

public sealed record CreatePolicyDraftRequest(
    [property: Required, MaxLength(120)] string Name,
    [property: Required, MaxLength(2000)] string Description,
    [property: Required, MinLength(1), MaxLength(50)] IReadOnlyList<PolicyRuleDto> Rules) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (Rules.Count > 50)
        {
            yield return new ValidationResult("Rules count cannot exceed 50.", [nameof(Rules)]);
        }
    }
}
