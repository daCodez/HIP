using FluentValidation;

namespace HIP.ApiService.Features.Identity;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class GetIdentityValidator : AbstractValidator<GetIdentityQuery>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public GetIdentityValidator()
    {
        RuleFor(x => x.Id).NotEmpty(); // validation
    }
}
