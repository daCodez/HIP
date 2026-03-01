using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Messages;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="Request">The Request value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed record SignMessageCommand(SignMessageRequestDto Request) : IRequest<SignMessageResultDto>;
