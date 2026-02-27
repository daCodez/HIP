using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Messages;

public sealed record SignMessageCommand(SignMessageRequestDto Request) : IRequest<SignMessageResultDto>;
