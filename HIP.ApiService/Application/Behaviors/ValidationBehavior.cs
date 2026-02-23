using FluentValidation;
using MediatR;

namespace HIP.ApiService.Application.Behaviors;

public sealed class ValidationBehavior<TRequest, TResponse>(IEnumerable<IValidator<TRequest>> validators, ILogger<ValidationBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); // validation

        if (!validators.Any())
        {
            return await next(); // performance awareness: skip extra work when no validators
        }

        var context = new ValidationContext<TRequest>(request);
        var failures = validators
            .Select(v => v.Validate(context))
            .SelectMany(result => result.Errors)
            .Where(f => f is not null)
            .ToArray();

        if (failures.Length != 0)
        {
            logger.LogWarning("Validation failure for {RequestType}: {FailuresCount}", typeof(TRequest).Name, failures.Length); // security awareness: logs counts only
            throw new ValidationException(failures);
        }

        return await next();
    }
}
