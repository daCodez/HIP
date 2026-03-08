using System.ComponentModel.DataAnnotations;

namespace HIP.Security.Api.Contracts;

public sealed record ReplayCampaignRequest([property: Required] Guid CampaignId, [property: Range(1, 25)] int ReplayCount = 1);
