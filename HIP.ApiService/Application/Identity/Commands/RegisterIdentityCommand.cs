using MediatR;

namespace HIP.ApiService.Application.Identity.Commands;

// TODO(HIP): implement persistence-backed registration flow in a later milestone.
public sealed record RegisterIdentityCommand(string Id, string PublicKeyRef) : IRequest<bool>;
