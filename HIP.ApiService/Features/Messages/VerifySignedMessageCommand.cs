using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Messages;

public sealed record VerifySignedMessageCommand(SignedMessageDto Message) : IRequest<VerifyMessageResultDto>;
