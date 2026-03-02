using FluentValidation;

namespace HIP.ApiService.Features.Status;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class GetStatusValidator : AbstractValidator<GetStatusQuery>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public GetStatusValidator()
    {
        RuleFor(x => x).NotNull(); // validation
    }
}
