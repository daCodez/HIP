using FluentValidation;

namespace HIP.ApiService.Features.Status;

public sealed class GetStatusValidator : AbstractValidator<GetStatusQuery>
{
    public GetStatusValidator()
    {
        RuleFor(x => x).NotNull(); // validation
    }
}
