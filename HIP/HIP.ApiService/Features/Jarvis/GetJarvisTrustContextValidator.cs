using FluentValidation;

namespace HIP.ApiService.Features.Jarvis;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class GetJarvisTrustContextValidator : AbstractValidator<GetJarvisTrustContextQuery>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public GetJarvisTrustContextValidator()
    {
        RuleFor(x => x.IdentityId).NotEmpty().MaximumLength(128);
    }
}