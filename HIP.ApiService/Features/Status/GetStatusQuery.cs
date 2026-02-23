using MediatR;

namespace HIP.ApiService.Features.Status;

public sealed record GetStatusQuery : IRequest<StatusResponse>;

public sealed record StatusResponse(string ServiceName, string AssemblyVersion, DateTimeOffset UtcTimestamp);
