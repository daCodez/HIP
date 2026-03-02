using FluentValidation;

namespace HIP.ApiService.Features.Messages;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class SignMessageValidator : AbstractValidator<SignMessageCommand>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
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