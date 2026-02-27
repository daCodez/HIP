using FluentValidation;

namespace HIP.ApiService.Features.Identity;

public sealed class GetIdentityValidator : AbstractValidator<GetIdentityQuery>
{
    public GetIdentityValidator()
    {
        RuleFor(x => x.Id).NotEmpty(); // validation
    }
}
