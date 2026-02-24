using FluentValidation;

namespace HIP.ApiService.Features.Messages;

public sealed class SignMessageValidator : AbstractValidator<SignMessageCommand>
{
    public SignMessageValidator()
    {
        RuleFor(x => x.Request).NotNull();
        RuleFor(x => x.Request.From).NotEmpty().MaximumLength(64);
        RuleFor(x => x.Request.To).NotEmpty().MaximumLength(64);
        RuleFor(x => x.Request.Body).NotEmpty().MaximumLength(4096);
        RuleFor(x => x.Request.Id).MaximumLength(128);
        RuleFor(x => x.Request.KeyId).MaximumLength(128);
    }
}