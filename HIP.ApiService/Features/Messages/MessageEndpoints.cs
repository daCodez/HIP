using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace HIP.ApiService.Features.Messages;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public static class MessageEndpoints
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="endpoints">The endpoints value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public static IEndpointRouteBuilder MapMessageEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/messages/sign", async (SignMessageRequestDto request, ISender sender, CancellationToken cancellationToken) =>
            {
                var result = await sender.Send(new SignMessageCommand(request), cancellationToken); // CQRS + validation pipeline
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(128 * 1024))
            .WithName("SignMessage")
            .WithTags("Messages")
            .Produces<SignMessageResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status413PayloadTooLarge)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/messages/verify", async (SignedMessageDto message, ISender sender, CancellationToken cancellationToken) =>
            {
                var result = await sender.Send(new VerifySignedMessageCommand(message), cancellationToken); // CQRS + validation pipeline
                return Results.Ok(result); // security awareness: verify result only
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(256 * 1024))
            .WithName("VerifySignedMessage")
            .WithTags("Messages")
            .Produces<VerifyMessageResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status413PayloadTooLarge)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/messages/verify-readonly", async (SignedMessageDto message, IMessageSignatureService signatureService, CancellationToken cancellationToken) =>
            {
                var result = await signatureService.VerifyReadOnlyAsync(message, cancellationToken);
                return Results.Ok(result);
            })
            .RequireRateLimiting("read-api")
            .WithMetadata(new RequestSizeLimitAttribute(256 * 1024))
            .WithName("VerifySignedMessageReadOnly")
            .WithTags("Messages")
            .Produces<VerifyMessageResultDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status413PayloadTooLarge)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
