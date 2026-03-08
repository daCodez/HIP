using System.ComponentModel.DataAnnotations;

namespace HIP.Security.Api.Contracts;

public sealed record RollbackPolicyRequest([property: Required, MaxLength(128)] string RequestedBy);
