using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using MediatR;

namespace HIP.ApiService.Features.Messages;

public static class MessageEndpoints
{
    public static IEndpointRouteBuilder MapMessageEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/messages/sign", async (SignMessageRequestDto request, ISender sender, CancellationToken cancellationToken) =>
            {
                var result = await sender.Send(new SignMessageCommand(request), cancellationToken); // CQRS + validation pipeline
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("SignMessage")
            .WithTags("Messages")
            .Produces<SignMessageResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/messages/verify", async (SignedMessageDto message, ISender sender, CancellationToken cancellationToken) =>
            {
                var result = await sender.Send(new VerifySignedMessageCommand(message), cancellationToken); // CQRS + validation pipeline
                return Results.Ok(result); // security awareness: verify result only
            })
            .RequireRateLimiting("read-api")
            .WithName("VerifySignedMessage")
            .WithTags("Messages")
            .Produces<VerifyMessageResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/messages/verify-readonly", async (SignedMessageDto message, IMessageSignatureService signatureService, CancellationToken cancellationToken) =>
            {
                var result = await signatureService.VerifyReadOnlyAsync(message, cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithName("VerifySignedMessageReadOnly")
            .WithTags("Messages")
            .Produces<VerifyMessageResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
