using System.Net.Http.Json;
using System.Text;
using HIP.Audit.Models;

namespace HIP.Sdk;

/// <summary>
/// Default HTTP implementation of <see cref="IHipSdkAdminClient"/>.
/// </summary>
public sealed class HipSdkAdminClient(HttpClient httpClient) : IHipSdkAdminClient
{
    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditEvent>> GetAuditEventsAsync(
        AuditQuery? query = null,
        string? identityId = null,
        CancellationToken cancellationToken = default)
    {
        var requestPath = BuildAuditPath(query, identityId);
        var result = await httpClient.GetFromJsonAsync<List<AuditEvent>>(requestPath, cancellationToken)
            ?? [];

        return result;
    }

    private static string BuildAuditPath(AuditQuery? query, string? identityId)
    {
        var q = query ?? new AuditQuery();

        var pairs = new List<string>
        {
            $"take={Uri.EscapeDataString(Math.Clamp(q.Take, 1, 200).ToString())}"
        };

        AppendIfPresent(pairs, "eventType", q.EventType);
        AppendIfPresent(pairs, "outcome", q.Outcome);
        AppendIfPresent(pairs, "reasonCode", q.ReasonCode);
        AppendIfPresent(pairs, "identityId", identityId ?? q.IdentityId);

        if (q.FromUtc is not null)
        {
            pairs.Add($"fromUtc={Uri.EscapeDataString(q.FromUtc.Value.ToString("O"))}");
        }

        if (q.ToUtc is not null)
        {
            pairs.Add($"toUtc={Uri.EscapeDataString(q.ToUtc.Value.ToString("O"))}");
        }

        var sb = new StringBuilder("/api/admin/audit");
        if (pairs.Count > 0)
        {
            sb.Append('?');
            sb.Append(string.Join('&', pairs));
        }

        return sb.ToString();
    }

    private static void AppendIfPresent(List<string> pairs, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            pairs.Add($"{key}={Uri.EscapeDataString(value)}");
        }
    }
}
