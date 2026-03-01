using MediatR;

namespace HIP.ApiService.Application.Identity.Commands;

/// <summary>
/// Command contract for registering a new identity and its public-key reference.
/// </summary>
/// <param name="Id">Identity identifier to register.</param>
/// <param name="PublicKeyRef">Reference to public-key material for the identity.</param>
// TODO(HIP): implement persistence-backed registration flow in a later milestone.
public sealed record RegisterIdentityCommand(string Id, string PublicKeyRef) : IRequest<bool>;
