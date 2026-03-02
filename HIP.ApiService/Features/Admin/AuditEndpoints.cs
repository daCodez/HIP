using System.Text;
using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.Extensions.Options;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Admin endpoints for querying HIP audit trail data.
/// </summary>
public static class AuditEndpoints
{
    /// <summary>
    /// Maps audit-trail admin endpoints.
    /// </summary>
    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
                "/api/admin/audit",
                async (
                    HttpContext httpContext,
                    int? take,
                    string? eventType,
                    string? identityId,
                    string? outcome,
                    string? reasonCode,
                    DateTimeOffset? fromUtc,
                    DateTimeOffset? toUtc,
                    IAuditTrail auditTrail,
                    IHipEnvelopeVerifier envelopeVerifier,
                    IIdentityService identityService,
                    IReputationService reputationService,
                    CancellationToken cancellationToken) =>
                {
                    var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
                    if (gate is not null)
                    {
                        return gate;
                    }

                    var query = new AuditQuery(
                        Take: Math.Clamp(take ?? 50, 1, 200),
                        EventType: eventType,
                        IdentityId: identityId,
                        Outcome: outcome,
                        ReasonCode: reasonCode,
                        FromUtc: fromUtc,
                        ToUtc: toUtc);

                    var items = await auditTrail.QueryAsync(query, cancellationToken);
                    return Results.Ok(items);
                })
            .RequireRateLimiting("read-api")
            .WithName("GetAuditEvents")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet(
                "/api/admin/audit/export",
                async (
                    HttpContext httpContext,
                    int? take,
                    string? format,
                    string? eventType,
                    string? identityId,
                    string? outcome,
                    string? reasonCode,
                    DateTimeOffset? fromUtc,
                    DateTimeOffset? toUtc,
                    IAuditTrail auditTrail,
                    IOptions<AuditRetentionOptions> options,
                    IHipEnvelopeVerifier envelopeVerifier,
                    IIdentityService identityService,
                    IReputationService reputationService,
                    CancellationToken cancellationToken) =>
                {
                    var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
                    if (gate is not null)
                    {
                        return gate;
                    }

                    var maxRows = Math.Clamp(options.Value.ExportMaxRows, 100, 10000);
                    var query = new AuditQuery(
                        Take: Math.Clamp(take ?? 500, 1, maxRows),
                        EventType: eventType,
                        IdentityId: identityId,
                        Outcome: outcome,
                        ReasonCode: reasonCode,
                        FromUtc: fromUtc,
                        ToUtc: toUtc);
                    var items = await auditTrail.QueryAsync(query, cancellationToken);

                    if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
                    {
                        var sb = new StringBuilder();
                        sb.AppendLine("id,createdAtUtc,eventType,subject,source,category,outcome,reasonCode,route,correlationId,latencyMs,detail");
                        foreach (var x in items)
                        {
                            sb.AppendLine(string.Join(',',
                                Escape(x.Id),
                                Escape(x.CreatedAtUtc.ToString("O")),
                                Escape(x.EventType),
                                Escape(x.Subject),
                                Escape(x.Source),
                                Escape(x.Category),
                                Escape(x.Outcome),
                                Escape(x.ReasonCode),
                                Escape(x.Route),
                                Escape(x.CorrelationId),
                                Escape(x.LatencyMs?.ToString("0.##")),
                                Escape(x.Detail)));
                        }

                        return Results.File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv", "hip-audit-export.csv");
                    }

                    return Results.Ok(new { count = items.Count, items });
                })
            .RequireRateLimiting("read-api")
            .WithName("ExportAuditEvents")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }

    private static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var v = value.Replace("\"", "\"\"");
        return $"\"{v}\"";
    }
}
