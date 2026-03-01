using MediatR;
using System.Reflection;

namespace HIP.ApiService.Features.Status;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="logger">The logger value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed class GetStatusHandler(ILogger<GetStatusHandler> logger) : IRequestHandler<GetStatusQuery, StatusResponse>
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="request">The request value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public Task<StatusResponse> Handle(GetStatusQuery request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); // validation
        logger.LogInformation("Handling HIP status query"); // logging

        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
        var response = new StatusResponse("HIP", version, DateTimeOffset.UtcNow); // security awareness: no sensitive values exposed

        return Task.FromResult(response); // performance awareness: synchronous completion path
    }
}
