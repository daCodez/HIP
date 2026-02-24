using FluentValidation;

namespace HIP.ApiService.Features.Messages;

public sealed class VerifySignedMessageValidator : AbstractValidator<VerifySignedMessageCommand>
{
    public VerifySignedMessageValidator()
    {
        RuleFor(x => x.Message).NotNull();
        RuleFor(x => x.Message.Id).NotEmpty().MaximumLength(128);
        RuleFor(x => x.Message.From).NotEmpty().MaximumLength(64);
        RuleFor(x => x.Message.To).NotEmpty().MaximumLength(64);
        RuleFor(x => x.Message.Body).NotEmpty().MaximumLength(4096);
        RuleFor(x => x.Message.SignatureBase64).NotEmpty().MaximumLength(1024);
        RuleFor(x => x.Message.KeyId).MaximumLength(128);
        RuleFor(x => x.Message.CreatedAtUtc).NotNull();
    }
}