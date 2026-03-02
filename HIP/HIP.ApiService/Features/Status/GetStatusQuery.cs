using MediatR;

namespace HIP.ApiService.Features.Status;

/// <summary>
/// Gets or sets the value associated with this public contract member.
/// </summary>
public sealed record GetStatusQuery : IRequest<StatusResponse>;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="ServiceName">The ServiceName value used by this operation.</param>
/// <param name="AssemblyVersion">The AssemblyVersion value used by this operation.</param>
/// <param name="UtcTimestamp">The UtcTimestamp value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed record StatusResponse(string ServiceName, string AssemblyVersion, DateTimeOffset UtcTimestamp);
