using FluentValidation;

namespace HIP.ApiService.Features.Jarvis;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class EvaluateJarvisToolAccessValidator : AbstractValidator<EvaluateJarvisToolAccessCommand>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public EvaluateJarvisToolAccessValidator()
    {
        RuleFor(x => x.Request.IdentityId).NotEmpty().MaximumLength(128);
        RuleFor(x => x.Request.ToolName).NotEmpty().MaximumLength(128);
        RuleFor(x => x.Request.RiskLevel)
            .NotEmpty()
            .Must(x => x is "low" or "medium" or "high")
            .WithMessage("RiskLevel must be one of: low, medium, high.");
    }
}