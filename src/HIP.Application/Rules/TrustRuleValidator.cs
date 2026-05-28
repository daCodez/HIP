using FluentValidation;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class TrustRuleValidator : AbstractValidator<TrustRule>
{
    public TrustRuleValidator()
    {
        RuleFor(rule => rule.Name).NotEmpty();
        RuleFor(rule => rule.Mode).IsInEnum();
        RuleFor(rule => rule.Severity).IsInEnum();
        RuleFor(rule => rule.Conditions).NotEmpty();
        RuleFor(rule => rule.Actions).NotEmpty();
        RuleFor(rule => rule.ConfidenceScore).InclusiveBetween(0, 100);
        RuleFor(rule => rule.Version).GreaterThanOrEqualTo(1);

        RuleForEach(rule => rule.Conditions).ChildRules(condition =>
        {
            condition.RuleFor(item => item.Field)
                .Must(field => SupportedRuleFields.Values.Contains(field))
                .WithMessage("Unsupported condition field.");
            condition.RuleFor(item => item.Operator).IsInEnum();
            condition.RuleFor(item => item.Value.GetRawText()).NotEmpty();
        });

        RuleForEach(rule => rule.Actions).ChildRules(action =>
        {
            action.RuleFor(item => item.Type).IsInEnum();
            action.RuleFor(item => item.Value.GetRawText()).NotEmpty();
        });

        RuleFor(rule => rule.RequiresApproval)
            .Equal(true)
            .When(RuleValidationConstants.IsHighImpact)
            .WithMessage("High-impact rules require approval.");
    }
}
