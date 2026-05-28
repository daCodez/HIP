using FluentValidation;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class ReviewItemValidator : AbstractValidator<ReviewItem>
{
    public ReviewItemValidator()
    {
        RuleFor(item => item.Title).NotEmpty();
        RuleFor(item => item.TargetType).IsInEnum();
        RuleFor(item => item.TargetId).NotEmpty();
        RuleFor(item => item.ReviewType).IsInEnum();
        RuleFor(item => item.Status).IsInEnum();
        RuleFor(item => item.Priority).IsInEnum();
    }
}

public sealed class AppealRequestValidator : AbstractValidator<AppealRequest>
{
    public AppealRequestValidator()
    {
        RuleFor(appeal => appeal.TargetType).IsInEnum();
        RuleFor(appeal => appeal.TargetId).NotEmpty();
        RuleFor(appeal => appeal.Reason).NotEmpty();
        RuleFor(appeal => appeal.SubmittedByHash).NotEmpty();
        RuleFor(appeal => appeal.Status).IsInEnum();
    }
}

public sealed class ReputationOverrideRequestValidator : AbstractValidator<ReputationOverrideRequest>
{
    public ReputationOverrideRequestValidator()
    {
        RuleFor(request => request.TargetType).IsInEnum();
        RuleFor(request => request.TargetId).NotEmpty();
        RuleFor(request => request.CurrentScore).InclusiveBetween(0, 100);
        RuleFor(request => request.RequestedScore).InclusiveBetween(0, 100);
        RuleFor(request => request.Reason).NotEmpty();
        RuleFor(request => request.RequiredApprovalCount).InclusiveBetween(1, 2);
        RuleFor(request => request.Status).IsInEnum();
    }
}
