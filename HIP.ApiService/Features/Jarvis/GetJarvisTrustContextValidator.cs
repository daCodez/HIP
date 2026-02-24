using FluentValidation;

namespace HIP.ApiService.Features.Jarvis;

public sealed class GetJarvisTrustContextValidator : AbstractValidator<GetJarvisTrustContextQuery>
{
    public GetJarvisTrustContextValidator()
    {
        RuleFor(x => x.IdentityId).NotEmpty().MaximumLength(128);
    }
}