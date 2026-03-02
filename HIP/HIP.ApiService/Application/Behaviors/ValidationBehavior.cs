using FluentValidation;
using MediatR;

namespace HIP.ApiService.Application.Behaviors;

/// <summary>
/// MediatR pipeline behavior that executes FluentValidation validators for each request.
/// </summary>
/// <typeparam name="TRequest">Request type passing through the pipeline.</typeparam>
/// <typeparam name="TResponse">Response type returned by the request handler.</typeparam>
public sealed class ValidationBehavior<TRequest, TResponse>(IEnumerable<IValidator<TRequest>> validators, ILogger<ValidationBehavior<TRequest, TResponse>> logger)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    /// <summary>
    /// Validates request payload before invoking the next handler in the MediatR chain.
    /// </summary>
    /// <param name="request">Incoming request instance.</param>
    /// <param name="next">Delegate that invokes the next pipeline component/handler.</param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <returns>Handler response when validation succeeds.</returns>
    /// <exception cref="ValidationException">Thrown when validation failures are detected.</exception>
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
