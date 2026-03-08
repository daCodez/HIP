using System.ComponentModel.DataAnnotations;

namespace HIP.Security.Api.Contracts;

public sealed record ActivatePolicyRequest(
    [property: Required, MaxLength(128)] string AuthorId,
    [property: Required, MaxLength(128)] string ReviewerId,
    [property: Required, MaxLength(128)] string ApproverId,
    [property: MaxLength(128)] string? ChangeTicket);
