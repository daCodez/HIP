using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Messages;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="Message">The Message value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed record VerifySignedMessageCommand(SignedMessageDto Message) : IRequest<VerifyMessageResultDto>;
