using System.Diagnostics;
using System.Text;
using System.Text.Json;
using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;

namespace HIP.ApiService.Features.Admin;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public static class SecurityEndpoints
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="endpoints">The endpoints value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public static IEndpointRouteBuilder MapSecurityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        async Task<IResult> securityStatusHandler(HttpContext httpContext, ISecurityEventCounter counter, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            return Results.Ok(counter.Snapshot());
        }

        async Task<IResult> securityEventsHandler(HttpContext httpContext, int? take, ISecurityRejectLog rejectLog, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null)
            {
                return gate;
            }

            var count = Math.Clamp(take ?? 10, 1, 100);
            return Results.Ok(rejectLog.Recent(count));
        }

        async Task<IResult> securityEventTypesHandler(HttpContext httpContext, IWebHostEnvironment env, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var path = Path.Combine(env.ContentRootPath, "SecurityEvents", "event-types.json");
            if (!File.Exists(path)) return Results.NotFound(new { code = "security.events.types.missing" });
            var json = await File.ReadAllTextAsync(path, cancellationToken);
            return Results.Content(json, "application/json", Encoding.UTF8);
        }

        async Task<IResult> securityEventSchemaHandler(HttpContext httpContext, IWebHostEnvironment env, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var path = Path.Combine(env.ContentRootPath, "SecurityEvents", "event-schema.json");
            if (!File.Exists(path)) return Results.NotFound(new { code = "security.events.schema.missing" });
            var json = await File.ReadAllTextAsync(path, cancellationToken);
            return Results.Content(json, "application/json", Encoding.UTF8);
        }

        async Task<IResult> validateSecurityEventHandler(HttpContext httpContext, JsonElement payload, IWebHostEnvironment env, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var typesPath = Path.Combine(env.ContentRootPath, "SecurityEvents", "event-types.json");
            if (!File.Exists(typesPath)) return Results.NotFound(new { code = "security.events.types.missing" });

            var allowedTypes = JsonSerializer.Deserialize<List<string>>(await File.ReadAllTextAsync(typesPath, cancellationToken)) ?? [];
            var errors = new List<string>();

            if (payload.ValueKind != JsonValueKind.Object)
            {
                return Results.BadRequest(new { valid = false, errors = new[] { "Payload must be a JSON object." } });
            }

            if (!payload.TryGetProperty("eventType", out var eventTypeEl) || eventTypeEl.ValueKind != JsonValueKind.String)
                errors.Add("eventType is required and must be a string.");
            else if (!allowedTypes.Contains(eventTypeEl.GetString() ?? string.Empty, StringComparer.OrdinalIgnoreCase))
                errors.Add($"eventType '{eventTypeEl.GetString()}' is not in allowed taxonomy.");

            if (!payload.TryGetProperty("timestampUtc", out var tsEl) || tsEl.ValueKind != JsonValueKind.String ||
                !DateTimeOffset.TryParse(tsEl.GetString(), out _))
                errors.Add("timestampUtc is required and must be a valid ISO date-time string.");

            var allowedSeverity = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Info", "Warning", "High", "Critical" };
            if (!payload.TryGetProperty("severity", out var sevEl) || sevEl.ValueKind != JsonValueKind.String ||
                !allowedSeverity.Contains(sevEl.GetString() ?? string.Empty))
                errors.Add("severity is required and must be one of: Info, Warning, High, Critical.");

            var allowedDecision = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Allow", "Warn", "Challenge", "Block", "Quarantine", "Pending" };
            if (!payload.TryGetProperty("decision", out var decEl) || decEl.ValueKind != JsonValueKind.String ||
                !allowedDecision.Contains(decEl.GetString() ?? string.Empty))
                errors.Add("decision is required and must be one of: Allow, Warn, Challenge, Block, Quarantine, Pending.");

            if (payload.TryGetProperty("riskScore", out var riskEl) && riskEl.ValueKind == JsonValueKind.Number)
            {
                if (!riskEl.TryGetInt32(out var risk) || risk < 0 || risk > 100)
                    errors.Add("riskScore must be an integer between 0 and 100.");
            }

            if (payload.TryGetProperty("policyIdsTriggered", out var policyEl) && policyEl.ValueKind != JsonValueKind.Array)
                errors.Add("policyIdsTriggered must be an array when provided.");

            if (errors.Count > 0)
                return Results.BadRequest(new { valid = false, errors });

            return Results.Ok(new { valid = true, errors = Array.Empty<string>() });
        }

        async Task<IResult> evaluateRiskHandler(HttpContext httpContext, JsonElement payload, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            static int ReputationRiskPoints(int score) => score switch
            {
                >= 80 => 0,
                >= 50 => 10,
                >= 30 => 20,
                >= 10 => 30,
                _ => 40
            };

            var signals = new List<object>();
            var total = 0;

            if (payload.TryGetProperty("newDevice", out var newDeviceEl) && newDeviceEl.ValueKind == JsonValueKind.True)
            {
                total += 20;
                signals.Add(new { signal = "New device", points = 20 });
            }

            if (payload.TryGetProperty("mfa", out var mfaEl) && mfaEl.ValueKind == JsonValueKind.False)
            {
                total += 25;
                signals.Add(new { signal = "No MFA", points = 25 });
            }

            if (payload.TryGetProperty("reputation", out var repEl) && repEl.ValueKind == JsonValueKind.Number && repEl.TryGetInt32(out var repScore))
            {
                var pts = ReputationRiskPoints(repScore);
                total += pts;
                signals.Add(new { signal = $"Reputation {repScore}", points = pts });
            }

            if (payload.TryGetProperty("ipRisk", out var ipEl) && ipEl.ValueKind == JsonValueKind.String)
            {
                var ip = ipEl.GetString() ?? "low";
                var pts = ip.Equals("high", StringComparison.OrdinalIgnoreCase) ? 40 : ip.Equals("medium", StringComparison.OrdinalIgnoreCase) ? 20 : 0;
                total += pts;
                signals.Add(new { signal = $"IP risk {ip}", points = pts });
            }

            if (payload.TryGetProperty("torProxy", out var torEl) && torEl.ValueKind == JsonValueKind.True)
            {
                total += 50;
                signals.Add(new { signal = "Tor / proxy network", points = 50 });
            }

            if (payload.TryGetProperty("replayDetected", out var replayEl) && replayEl.ValueKind == JsonValueKind.True)
            {
                total += 80;
                signals.Add(new { signal = "Replay detected", points = 80 });
            }

            total = Math.Clamp(total, 0, 100);

            var level = total switch
            {
                < 30 => "Low",
                < 60 => "Medium",
                < 80 => "High",
                _ => "Critical"
            };

            var decision = total switch
            {
                < 30 => "Allow",
                < 60 => "Warn",
                < 80 => "Challenge",
                _ => "Block"
            };

            return Results.Ok(new
            {
                riskScore = total,
                level,
                decision,
                signals
            });
        }

        async Task<IResult> liveReplayHandler(HttpContext httpContext, JsonElement payload, IAuditTrail auditTrail, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            if (payload.ValueKind != JsonValueKind.Object)
            {
                return Results.BadRequest(new { code = "simulator.liveReplay.invalidPayload", reason = "payload must be JSON object" });
            }

            var actorId = payload.TryGetProperty("actorId", out var actorEl) ? actorEl.GetString() ?? "sim.unknown" : "sim.unknown";
            var eventType = payload.TryGetProperty("eventType", out var eventEl) ? eventEl.GetString() ?? "SIMULATOR_EVENT" : "SIMULATOR_EVENT";
            var expectedAction = payload.TryGetProperty("expectedAction", out var expectedEl) ? expectedEl.GetString() ?? "Allow" : "Allow";

            var events = payload.TryGetProperty("events", out var eventsEl) && eventsEl.ValueKind == JsonValueKind.Array
                ? eventsEl.EnumerateArray().ToArray()
                : Array.Empty<JsonElement>();

            var first = events.FirstOrDefault();
            var livePayload = first.ValueKind == JsonValueKind.Object && first.TryGetProperty("payload", out var pEl) && pEl.ValueKind == JsonValueKind.Object
                ? pEl
                : payload;

            var replayDetected = livePayload.TryGetProperty("replayDetected", out var replayEl) && replayEl.ValueKind == JsonValueKind.True;
            var impossibleTravel = livePayload.TryGetProperty("impossibleTravel", out var travelEl) && travelEl.ValueKind == JsonValueKind.True;
            var mfaMissing = livePayload.TryGetProperty("mfa", out var mfaEl) && mfaEl.ValueKind == JsonValueKind.False;
            var ipRisk = livePayload.TryGetProperty("ipRisk", out var ipEl) ? ipEl.GetString() ?? "low" : "low";
            var reputation = livePayload.TryGetProperty("reputation", out var repEl) && repEl.ValueKind == JsonValueKind.Number && repEl.TryGetInt32(out var repVal)
                ? repVal
                : await reputationService.GetScoreAsync(actorId, cancellationToken);

            var finalAction = "Allow";
            var severity = "Info";
            var httpStatus = StatusCodes.Status200OK;
            var auditEvent = eventType;
            var reputationImpact = "none";

            if (replayDetected)
            {
                finalAction = "Block";
                severity = "Critical";
                httpStatus = StatusCodes.Status403Forbidden;
                auditEvent = "TOKEN_REPLAY_BLOCKED";
                reputationImpact = "decrease";
            }
            else if (impossibleTravel || ipRisk.Equals("high", StringComparison.OrdinalIgnoreCase))
            {
                finalAction = "Block";
                severity = "Critical";
                httpStatus = StatusCodes.Status403Forbidden;
                auditEvent = "LOGIN_IMPOSSIBLE_TRAVEL";
                reputationImpact = "decrease";
            }
            else if (mfaMissing || ipRisk.Equals("medium", StringComparison.OrdinalIgnoreCase) || reputation < 40)
            {
                finalAction = "Challenge";
                severity = "High";
                httpStatus = StatusCodes.Status401Unauthorized;
                auditEvent = "MFA_CHALLENGE";
                reputationImpact = "watch";
            }

            if (reputationImpact == "decrease")
            {
                await reputationService.RecordSecurityEventAsync(actorId, auditEvent, cancellationToken);
            }

            var correlationId = Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString("n");
            await auditTrail.AppendAsync(new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: auditEvent,
                Subject: actorId,
                Source: "simulator.live",
                Detail: $"live-replay expected={expectedAction} actual={finalAction}",
                Category: "security",
                Outcome: finalAction,
                ReasonCode: finalAction.Equals(expectedAction, StringComparison.OrdinalIgnoreCase) ? "liveReplay.match" : "liveReplay.mismatch",
                Route: httpContext.Request.Path,
                CorrelationId: correlationId),
                cancellationToken);

            return Results.Ok(new
            {
                finalAction,
                severity,
                httpStatus,
                auditEvent,
                reputationImpact,
                correlationId
            });
        }

        async Task<IResult> usersDevicesHandler(HttpContext httpContext, DeviceRegistrationStore store, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            var rows = store.GetAll()
                .Select(x => new
                {
                    user = x.User,
                    email = x.Email,
                    device = x.Device,
                    deviceStatus = x.DeviceStatus,
                    lastSeen = x.LastSeenUtc
                })
                .ToArray();

            return Results.Ok(rows);
        }

        async Task<IResult> usersDevicesHistoryHandler(HttpContext httpContext, string email, string device, DeviceRegistrationStore store, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(device))
            {
                return Results.BadRequest(new { code = "device.history.validation", reason = "email and device are required" });
            }

            var rows = store.GetHistory(email, device)
                .Select(x => new
                {
                    email = x.Email,
                    device = x.Device,
                    action = x.Action,
                    status = x.Status,
                    note = x.Note,
                    actor = x.Actor,
                    timestamp = x.TimestampUtc
                })
                .ToArray();

            return Results.Ok(rows);
        }

        async Task<IResult> registerDeviceHandler(HttpContext httpContext, JsonElement payload, DeviceRegistrationStore store, IAuditTrail auditTrail, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            if (payload.ValueKind != JsonValueKind.Object)
            {
                return Results.BadRequest(new { code = "device.register.invalidPayload", reason = "payload must be JSON object" });
            }

            var user = payload.TryGetProperty("user", out var userEl) ? (userEl.GetString() ?? string.Empty).Trim() : string.Empty;
            var email = payload.TryGetProperty("email", out var emailEl) ? (emailEl.GetString() ?? string.Empty).Trim() : string.Empty;
            var device = payload.TryGetProperty("device", out var deviceEl) ? (deviceEl.GetString() ?? string.Empty).Trim() : string.Empty;
            var actor = payload.TryGetProperty("actor", out var actorEl) ? (actorEl.GetString() ?? string.Empty).Trim() : string.Empty;

            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(device))
            {
                return Results.BadRequest(new { code = "device.register.validation", reason = "user, email, and device are required" });
            }

            if (string.IsNullOrWhiteSpace(actor))
            {
                actor = "admin";
            }

            var entry = store.Register(new DeviceRegistrationEntry(
                User: user,
                Email: email,
                Device: device,
                DeviceStatus: "Pending",
                LastSeenUtc: DateTime.UtcNow), actor);

            await auditTrail.AppendAsync(new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "device.registration.created",
                Subject: email,
                Source: "admin",
                Detail: $"Device '{device}' registered for user '{user}'",
                Category: "device",
                Outcome: "pending",
                ReasonCode: "device.registration.pending",
                Route: httpContext.Request.Path,
                CorrelationId: Activity.Current?.TraceId.ToString()),
                cancellationToken);

            return Results.Ok(new
            {
                user = entry.User,
                email = entry.Email,
                device = entry.Device,
                deviceStatus = entry.DeviceStatus,
                lastSeen = entry.LastSeenUtc
            });
        }

        async Task<IResult> deviceActionHandler(HttpContext httpContext, JsonElement payload, DeviceRegistrationStore store, IAuditTrail auditTrail, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken)
        {
            var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
            if (gate is not null) return gate;

            if (payload.ValueKind != JsonValueKind.Object)
            {
                return Results.BadRequest(new { code = "device.action.invalidPayload", reason = "payload must be JSON object" });
            }

            var email = payload.TryGetProperty("email", out var emailEl) ? (emailEl.GetString() ?? string.Empty).Trim() : string.Empty;
            var device = payload.TryGetProperty("device", out var deviceEl) ? (deviceEl.GetString() ?? string.Empty).Trim() : string.Empty;
            var action = payload.TryGetProperty("action", out var actionEl) ? (actionEl.GetString() ?? string.Empty).Trim() : string.Empty;
            var note = payload.TryGetProperty("note", out var noteEl) ? (noteEl.GetString() ?? string.Empty).Trim() : string.Empty;
            var actor = payload.TryGetProperty("actor", out var actorEl) ? (actorEl.GetString() ?? string.Empty).Trim() : string.Empty;

            var status = action.ToLowerInvariant() switch
            {
                "approve" => "Trusted",
                "challenge" => "Pending",
                "block" => "Blocked",
                _ => string.Empty
            };

            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(device) || string.IsNullOrWhiteSpace(status) || string.IsNullOrWhiteSpace(note))
            {
                return Results.BadRequest(new { code = "device.action.validation", reason = "email, device, note, and valid action (approve|challenge|block) are required" });
            }

            if (string.IsNullOrWhiteSpace(actor))
            {
                actor = "admin";
            }

            var updated = store.UpdateStatus(email, device, status, action, note, actor);
            if (updated is null)
            {
                return Results.NotFound(new { code = "device.action.notFound", reason = "device registration not found" });
            }

            await auditTrail.AppendAsync(new AuditEvent(
                Id: Guid.NewGuid().ToString("n"),
                CreatedAtUtc: DateTimeOffset.UtcNow,
                EventType: "device.registration.status_updated",
                Subject: email,
                Source: "admin",
                Detail: $"Device '{device}' set to '{status}'. Note: {note}",
                Category: "device",
                Outcome: status.ToLowerInvariant(),
                ReasonCode: $"device.registration.{status.ToLowerInvariant()}",
                Route: httpContext.Request.Path,
                CorrelationId: Activity.Current?.TraceId.ToString()),
                cancellationToken);

            return Results.Ok(new
            {
                user = updated.User,
                email = updated.Email,
                device = updated.Device,
                deviceStatus = updated.DeviceStatus,
                lastSeen = updated.LastSeenUtc
            });
        }

        endpoints.MapGet("/api/admin/users-devices", usersDevicesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetUsersDevices")
            .WithSummary("Get users and device registrations")
            .WithTags("Admin", "Device")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/users-devices", usersDevicesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetUsersDevicesV1")
            .WithSummary("Get users and device registrations")
            .WithTags("Admin", "Device", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/users-devices/history", usersDevicesHistoryHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetUsersDevicesHistory")
            .WithSummary("Get action history for a registered device")
            .WithTags("Admin", "Device")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/users-devices/history", usersDevicesHistoryHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetUsersDevicesHistoryV1")
            .WithSummary("Get action history for a registered device")
            .WithTags("Admin", "Device", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/users-devices/register", registerDeviceHandler)
            .RequireRateLimiting("read-api")
            .WithName("RegisterUserDevice")
            .WithSummary("Register a new device")
            .WithTags("Admin", "Device")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/users-devices/register", registerDeviceHandler)
            .RequireRateLimiting("read-api")
            .WithName("RegisterUserDeviceV1")
            .WithSummary("Register a new device")
            .WithTags("Admin", "Device", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/users-devices/action", deviceActionHandler)
            .RequireRateLimiting("read-api")
            .WithName("DeviceRegistrationAction")
            .WithSummary("Approve/challenge/block a registered device")
            .WithTags("Admin", "Device")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/users-devices/action", deviceActionHandler)
            .RequireRateLimiting("read-api")
            .WithName("DeviceRegistrationActionV1")
            .WithSummary("Approve/challenge/block a registered device")
            .WithTags("Admin", "Device", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/security-status", securityStatusHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityStatus")
            .WithSummary("Get aggregate security status counters")
            .WithDescription("Returns current aggregate security counters (replay detections, expired messages, and policy blocks) for admin dashboard health views.")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/security-status", securityStatusHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityStatusV1")
            .WithSummary("Get aggregate security status counters")
            .WithDescription("Versioned alias of admin security status endpoint.")
            .WithTags("Admin", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/security-events", securityEventsHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityEvents")
            .WithSummary("Get recent security rejection events")
            .WithDescription("Returns recent security rejection events for investigation, including reason, identity, and timestamp. Supports optional take parameter.")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/security-events", securityEventsHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityEventsV1")
            .WithSummary("Get recent security rejection events")
            .WithDescription("Versioned alias of admin security events endpoint.")
            .WithTags("Admin", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/reputation/{identityId}/breakdown", async (HttpContext httpContext, string identityId, IHipEnvelopeVerifier envelopeVerifier, IIdentityService identityService, IReputationService reputationService, CancellationToken cancellationToken) =>
            {
                var gate = await AdminAccessPolicy.AuthorizeReadAsync(httpContext, envelopeVerifier, identityService, reputationService, cancellationToken);
                if (gate is not null)
                {
                    return gate;
                }

                var breakdown = await reputationService.GetScoreBreakdownAsync(identityId, cancellationToken);
                return Results.Ok(breakdown);
            })
            .RequireRateLimiting("read-api")
            .WithName("GetAdminReputationBreakdown")
            .WithSummary("Get reputation score breakdown for an identity")
            .WithDescription("Returns a reasoned score breakdown for the specified identity to explain current reputation and risk drivers.")
            .WithTags("Admin")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/security/events/types", securityEventTypesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityEventTypes")
            .WithSummary("Get canonical security event taxonomy")
            .WithDescription("Returns canonical event type list used by timeline and event producers.")
            .WithTags("Admin", "Security")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/security/events/types", securityEventTypesHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityEventTypesV1")
            .WithSummary("Get canonical security event taxonomy")
            .WithDescription("Versioned alias of security event taxonomy endpoint.")
            .WithTags("Admin", "Security", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/admin/security/events/schema", securityEventSchemaHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityEventSchema")
            .WithSummary("Get security event JSON schema")
            .WithDescription("Returns required fields and contract for security events used by timeline, alerts, and event ingestion.")
            .WithTags("Admin", "Security")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapGet("/api/v1/admin/security/events/schema", securityEventSchemaHandler)
            .RequireRateLimiting("read-api")
            .WithName("GetSecurityEventSchemaV1")
            .WithSummary("Get security event JSON schema")
            .WithDescription("Versioned alias of security event schema endpoint.")
            .WithTags("Admin", "Security", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/security/events/validate", validateSecurityEventHandler)
            .RequireRateLimiting("read-api")
            .WithName("ValidateSecurityEventPayload")
            .WithSummary("Validate a security event payload")
            .WithDescription("Validates payload shape and taxonomy alignment for security events before ingestion or sandbox replay.")
            .WithTags("Admin", "Security")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/security/events/validate", validateSecurityEventHandler)
            .RequireRateLimiting("read-api")
            .WithName("ValidateSecurityEventPayloadV1")
            .WithSummary("Validate a security event payload")
            .WithDescription("Versioned alias of security event payload validator.")
            .WithTags("Admin", "Security", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/security/risk/evaluate", evaluateRiskHandler)
            .RequireRateLimiting("read-api")
            .WithName("EvaluateSecurityRisk")
            .WithSummary("Evaluate composite security risk")
            .WithDescription("Computes a risk score from core signals (device, MFA, reputation, IP, replay) and returns level + decision.")
            .WithTags("Admin", "Security")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/security/risk/evaluate", evaluateRiskHandler)
            .RequireRateLimiting("read-api")
            .WithName("EvaluateSecurityRiskV1")
            .WithSummary("Evaluate composite security risk")
            .WithDescription("Versioned alias of composite security risk endpoint.")
            .WithTags("Admin", "Security", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/admin/simulator/live-replay", liveReplayHandler)
            .RequireRateLimiting("read-api")
            .WithName("RunLiveReplay")
            .WithSummary("Run simulator scenario against live API behavior")
            .WithDescription("Evaluates a replay payload through live enforcement logic, writes audit evidence, and returns action/severity/http/audit/reputation outputs for simulator comparison.")
            .WithTags("Admin", "Security", "Simulator")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        endpoints.MapPost("/api/v1/admin/simulator/live-replay", liveReplayHandler)
            .RequireRateLimiting("read-api")
            .WithName("RunLiveReplayV1")
            .WithSummary("Run simulator scenario against live API behavior")
            .WithDescription("Versioned alias of live replay endpoint.")
            .WithTags("Admin", "Security", "Simulator", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status429TooManyRequests);

        return endpoints;
    }
}
