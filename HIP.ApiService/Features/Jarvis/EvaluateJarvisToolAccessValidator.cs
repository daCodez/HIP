using FluentValidation;

namespace HIP.ApiService.Features.Jarvis;

public sealed class EvaluateJarvisToolAccessValidator : AbstractValidator<EvaluateJarvisToolAccessCommand>
{
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