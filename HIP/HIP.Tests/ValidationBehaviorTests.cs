using FluentValidation;
using HIP.ApiService.Application.Behaviors;
using MediatR;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class ValidationBehaviorTests
{
    private sealed record FakeRequest(string Value) : IRequest<string>;

    private sealed class FakeRequestValidator : AbstractValidator<FakeRequest>
    {
        public FakeRequestValidator() => RuleFor(x => x.Value).NotEmpty();
    }

    [Test]
    public void Handle_InvalidRequest_ThrowsValidationException()
    {
        var validators = new IValidator<FakeRequest>[] { new FakeRequestValidator() };
        var behavior = new ValidationBehavior<FakeRequest, string>(validators, NullLogger<ValidationBehavior<FakeRequest, string>>.Instance);

        Assert.That(async () => await behavior.Handle(new FakeRequest(string.Empty), () => Task.FromResult("ok"), CancellationToken.None),
            Throws.TypeOf<ValidationException>());
    }

    [Test]
    public async Task Handle_ValidRequest_CallsNext()
    {
        var validators = new IValidator<FakeRequest>[] { new FakeRequestValidator() };
        var behavior = new ValidationBehavior<FakeRequest, string>(validators, NullLogger<ValidationBehavior<FakeRequest, string>>.Instance);

        var result = await behavior.Handle(new FakeRequest("good"), () => Task.FromResult("ok"), CancellationToken.None);

        Assert.That(result, Is.EqualTo("ok"));
    }
    [Test]
    public async Task Handle_NoValidators_CallsNext()
    {
        var validators = Array.Empty<IValidator<FakeRequest>>();
        var behavior = new ValidationBehavior<FakeRequest, string>(validators, NullLogger<ValidationBehavior<FakeRequest, string>>.Instance);

        var result = await behavior.Handle(new FakeRequest("anything"), () => Task.FromResult("ok"), CancellationToken.None);

        Assert.That(result, Is.EqualTo("ok"));
    }

}
