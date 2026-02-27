using FluentValidation;

namespace HIP.ApiService.Features.Reputation;

public sealed class GetReputationValidator : AbstractValidator<GetReputationQuery>
{
    public GetReputationValidator()
    {
        RuleFor(x => x.IdentityId).NotEmpty(); // validation
    }
}
