using FluentValidation;

namespace HIP.ApiService.Features.Jarvis;

public sealed class EvaluateJarvisPolicyValidator : AbstractValidator<EvaluateJarvisPolicyCommand>
{
    public EvaluateJarvisPolicyValidator()
    {
        RuleFor(x => x.Request.IdentityId).NotEmpty().MaximumLength(128);
        RuleFor(x => x.Request.UserText).NotEmpty().MaximumLength(8000);
        RuleFor(x => x.Request.ContextNote).MaximumLength(1024);
        RuleFor(x => x.Request.ToolName).MaximumLength(128);
        RuleFor(x => x.Request.RiskLevel)
            .NotEmpty()
            .Must(x => x is "low" or "medium" or "high")
            .WithMessage("RiskLevel must be one of: low, medium, high.");
    }
}