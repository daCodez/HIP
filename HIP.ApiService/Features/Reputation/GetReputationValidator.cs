using FluentValidation;

namespace HIP.ApiService.Features.Reputation;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class GetReputationValidator : AbstractValidator<GetReputationQuery>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public GetReputationValidator()
    {
        RuleFor(x => x.IdentityId).NotEmpty(); // validation
    }
}
