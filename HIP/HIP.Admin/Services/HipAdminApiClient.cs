using System.Text;
using System.Text.Json;
using HIP.Admin.Models;

namespace HIP.Admin.Services;

public sealed class HipAdminApiClient(HttpClient httpClient, AdminContextService context)
{
    public async Task<ApiResult<List<DashboardMetric>>> GetDashboardMetricsAsync(CancellationToken ct = default)
        => await ExecuteWithMockFallback(async () =>
        {
            using var doc = await GetJsonDocumentWithRetryAsync("api/admin/security-status", ct);
            var root = doc?.RootElement;
            if (root is null || root.Value.ValueKind != JsonValueKind.Object)
            {
                return [];
            }

            static long ReadLong(JsonElement obj, string name)
                => obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out var n) ? n : 0;

            var replay = ReadLong(root.Value, "replayDetected");
            var expired = ReadLong(root.Value, "messageExpired");
            var blocked = ReadLong(root.Value, "policyBlocked");
            var totalRisk = replay + expired + blocked;
            var score = (int)Math.Clamp(100 - (replay * 6) - (blocked * 4) - (expired * 2), 0, 100);

            return
            [
                new() { Title = "Security Score", Value = $"{score}", Delta = totalRisk == 0 ? "Stable" : $"-{totalRisk}", Trend = totalRisk == 0 ? "up" : "down" },
                new() { Title = "Blocked Attempts", Value = blocked.ToString(), Delta = blocked == 0 ? "No change" : "+recent", Trend = blocked == 0 ? "up" : "down" },
                new() { Title = "Replay Detections", Value = replay.ToString(), Delta = replay == 0 ? "None" : "+recent", Trend = replay == 0 ? "up" : "down" },
                new() { Title = "Expired Messages", Value = expired.ToString(), Delta = expired == 0 ? "None" : "+recent", Trend = expired == 0 ? "up" : "down" }
            ];
        }, MockMetrics(), "api/admin/security-status");

    public async Task<ApiResult<List<ActivityItem>>> GetActivityAsync(CancellationToken ct = default)
        => await ExecuteWithMockFallback(async () =>
        {
            using var doc = await GetJsonDocumentWithRetryAsync("api/admin/security-events?take=25", ct);
            var root = doc?.RootElement;
            if (root is null || root.Value.ValueKind != JsonValueKind.Array)
            {
                return [];
            }

            var list = new List<ActivityItem>();
            foreach (var e in root.Value.EnumerateArray())
            {
                var reason = e.TryGetProperty("reason", out var reasonEl) ? reasonEl.GetString() ?? "Security reject" : "Security reject";
                var identity = e.TryGetProperty("identityId", out var idEl) ? idEl.GetString() ?? "unknown" : "unknown";
                var ts = e.TryGetProperty("utcTimestamp", out var tsEl) && tsEl.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(tsEl.GetString(), out var dto)
                    ? dto.UtcDateTime
                    : DateTime.UtcNow;

                list.Add(new ActivityItem
                {
                    Timestamp = ts,
                    Actor = identity,
                    Action = reason
                });
            }

            return list;
        }, MockActivity(), "api/admin/security-events?take=25");

    public Task<ApiResult<List<SecurityCheck>>> GetSecurityChecksAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<SecurityCheck>>("api/v1/admin/security", ct)!, MockSecurity(), "api/v1/admin/security");

    public Task<ApiResult<List<UserDeviceRecord>>> GetUsersDevicesAsync(CancellationToken ct = default)
        => ExecuteWithMockFallback(() => httpClient.GetFromJsonAsync<List<UserDeviceRecord>>("api/v1/admin/users-devices", ct)!, MockUsers(), "api/v1/admin/users-devices");

    public async Task<ApiResult<List<PolicyRule>>> GetPolicyRulesAsync(CancellationToken ct = default)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<List<PolicyRule>>.Ok(MockRules());
        }

        try
        {
            var list = await httpClient.GetFromJsonAsync<List<PolicyRule>>("api/v1/admin/policy", ct);
            if (list is { Count: > 0 })
            {
                return ApiResult<List<PolicyRule>>.Ok(list);
            }
        }
        catch
        {
            // fall through to effective-policy adapter
        }

        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>("api/v1/policy/effective", ct);
            var root = doc?.RootElement;
            if (root is not null && root.Value.TryGetProperty("requiredScores", out var scores))
            {
                var low = scores.TryGetProperty("low", out var lowEl) && lowEl.TryGetInt32(out var l) ? l : 30;
                var medium = scores.TryGetProperty("medium", out var medEl) && medEl.TryGetInt32(out var m) ? m : 50;
                var high = scores.TryGetProperty("high", out var highEl) && highEl.TryGetInt32(out var h) ? h : 70;

                var adapted = new List<PolicyRule>
                {
                    new() { RuleId = "POL-LOW", Name = $"Low risk threshold >= {low}", Category = "Reputation", Condition = $"reputation >= {low}", Action = "Warn", Severity = "Medium", Enabled = true },
                    new() { RuleId = "POL-MED", Name = $"Medium risk threshold >= {medium}", Category = "Reputation", Condition = $"reputation >= {medium}", Action = "Challenge", Severity = "High", Enabled = true },
                    new() { RuleId = "POL-HIGH", Name = $"High risk threshold >= {high}", Category = "Reputation", Condition = $"reputation >= {high}", Action = "Allow", Severity = "Critical", Enabled = true },
                    new() { RuleId = "POL-REPLAY", Name = "Replay protection required", Category = "Token", Condition = "replayDetected == true", Action = "Block", Severity = "Critical", Enabled = true },
                    new() { RuleId = "POL-EXP", Name = "Token expiry enforced", Category = "Token", Condition = "tokenExpired == true", Action = "Block", Severity = "High", Enabled = true }
                };

                return ApiResult<List<PolicyRule>>.Ok(adapted);
            }
        }
        catch (Exception ex)
        {
            return ApiResult<List<PolicyRule>>.Fail($"Failed to load data from 'api/v1/admin/policy' and fallback 'api/v1/policy/effective'. {ex.Message}");
        }

        return ApiResult<List<PolicyRule>>.Fail("Failed to load data from 'api/v1/admin/policy' and fallback 'api/v1/policy/effective'. Empty response.");
    }

    public async Task<ApiResult<List<ReputationWatchItem>>> GetTopRiskIdentitiesAsync(CancellationToken ct = default)
        => await ExecuteWithMockFallback(async () =>
        {
            using var doc = await GetJsonDocumentWithRetryAsync("api/plugins/identity/insights/top-risk?take=5", ct);
            var root = doc?.RootElement;
            if (root is null || !root.Value.TryGetProperty("identities", out var identities) || identities.ValueKind != JsonValueKind.Array)
            {
                return [];
            }

            var items = new List<ReputationWatchItem>();
            foreach (var x in identities.EnumerateArray())
            {
                var id = x.TryGetProperty("identityId", out var idEl) ? idEl.GetString() ?? "unknown" : "unknown";
                var blocked = x.TryGetProperty("blocked", out var bEl) && bEl.TryGetInt32(out var b) ? b : 0;
                var review = x.TryGetProperty("review", out var rEl) && rEl.TryGetInt32(out var r) ? r : 0;
                var score = Math.Clamp(100 - (blocked * 20) - (review * 10), 0, 100);

                items.Add(new ReputationWatchItem
                {
                    IdentityId = id,
                    Score = score,
                    Blocked = blocked,
                    Review = review
                });
            }

            return items;
        }, MockReputationWatch(), "api/plugins/identity/insights/top-risk?take=5");

    public async Task<ApiResult<List<AuthzPolicyRule>>> GetAuthzPolicyRulesAsync(CancellationToken ct = default)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<List<AuthzPolicyRule>>.Ok(
            [
                new() { RuleId = "AUTHZ-001", Name = "Support can view audit logs", Role = "Support", Resource = "audit", Action = "read", Decision = "Allow", Enabled = true },
                new() { RuleId = "AUTHZ-002", Name = "Support cannot export audit logs", Role = "Support", Resource = "audit", Action = "export", Decision = "Deny", Enabled = true }
            ]);
        }

        try
        {
            var data = await httpClient.GetFromJsonAsync<List<AuthzPolicyRule>>("api/v1/admin/authz-policies", ct);
            return ApiResult<List<AuthzPolicyRule>>.Ok(data ?? []);
        }
        catch (Exception ex)
        {
            return ApiResult<List<AuthzPolicyRule>>.Fail($"Failed to load data from 'api/v1/admin/authz-policies'. {ex.Message}");
        }
    }

    public async Task<ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>> SimulateAuthzAsync(string jsonInput, CancellationToken ct = default)
    {
        try
        {
            using var req = new StringContent(jsonInput, Encoding.UTF8, "application/json");
            using var response = await httpClient.PostAsync("api/v1/admin/authz/simulate", req, ct);
            response.EnsureSuccessStatusCode();

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var root = doc.RootElement;
            var decision = root.TryGetProperty("decision", out var dEl) ? dEl.GetString() ?? "DENY" : "DENY";
            var triggered = root.TryGetProperty("triggeredRules", out var tEl) && tEl.ValueKind == JsonValueKind.Array
                ? tEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToList()
                : new List<string>();
            var actions = root.TryGetProperty("actions", out var aEl) && aEl.ValueKind == JsonValueKind.Array
                ? aEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToList()
                : new List<string>();
            var trace = root.TryGetProperty("trace", out var trEl) && trEl.ValueKind == JsonValueKind.Array
                ? trEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToList()
                : new List<string>();

            return ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>.Ok((decision, triggered, actions, trace));
        }
        catch (Exception ex)
        {
            return ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>.Fail($"Failed to load data from 'api/v1/admin/authz/simulate'. {ex.Message}");
        }
    }

    public async Task<ApiResult<PolicyRule>> GeneratePolicyDraftAsync(string prompt, CancellationToken ct = default)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<PolicyRule>.Ok(new PolicyRule
            {
                RuleId = "AI-LOCAL",
                Name = "AI Draft: Low reputation link block",
                Category = "Messaging",
                Condition = "reputation < 20 && sendingLink == true",
                Action = "Block",
                Severity = "Critical",
                Enabled = false
            });
        }

        try
        {
            var payload = JsonSerializer.Serialize(new { prompt });
            using var req = new StringContent(payload, Encoding.UTF8, "application/json");
            using var res = await httpClient.PostAsync("api/v1/admin/policy/ai-draft", req, ct);
            res.EnsureSuccessStatusCode();
            var json = await res.Content.ReadAsStringAsync(ct);
            var rule = JsonSerializer.Deserialize<PolicyRule>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return rule is null ? ApiResult<PolicyRule>.Fail("Empty AI draft response.") : ApiResult<PolicyRule>.Ok(rule);
        }
        catch (Exception ex)
        {
            return ApiResult<PolicyRule>.Fail($"Failed to load data from 'api/v1/admin/policy/ai-draft'. {ex.Message}");
        }
    }

    public async Task<ApiResult<bool>> UpsertPolicyRuleAsync(PolicyRule rule, CancellationToken ct = default)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                ruleId = rule.RuleId,
                name = rule.Name,
                category = rule.Category,
                condition = rule.Condition,
                action = rule.Action,
                severity = rule.Severity,
                enabled = rule.Enabled
            });
            using var req = new StringContent(payload, Encoding.UTF8, "application/json");
            using var res = await httpClient.PostAsync("api/v1/admin/policy", req, ct);
            res.EnsureSuccessStatusCode();
            return ApiResult<bool>.Ok(true);
        }
        catch (Exception ex)
        {
            return ApiResult<bool>.Fail($"Failed to load data from 'api/v1/admin/policy'. {ex.Message}");
        }
    }

    public async Task<ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>> SimulatePolicyAsync(string jsonInput, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(jsonInput))
        {
            return ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>.Fail("Sandbox input is required.");
        }

        if (context.MockModeEnabled)
        {
            return ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>.Ok((
                "CHALLENGE",
                new List<string> { "Require MFA", "Untrusted Device" },
                new List<string> { "Require MFA", "Send device alert" },
                new List<string>
                {
                    "✔ LoginPolicy.MfaRequired → triggered",
                    "✔ DevicePolicy.TrustedDevice → triggered",
                    "✘ ReputationPolicy.LowScore → not triggered"
                }));
        }

        try
        {
            using var req = new StringContent(jsonInput, Encoding.UTF8, "application/json");
            using var response = await httpClient.PostAsync("api/v1/admin/policy/simulate", req, ct);
            response.EnsureSuccessStatusCode();

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var root = doc.RootElement;

            var decision = root.TryGetProperty("decision", out var dEl) ? dEl.GetString() ?? "ALLOW" : "ALLOW";
            var triggered = root.TryGetProperty("triggeredRules", out var tEl) && tEl.ValueKind == JsonValueKind.Array
                ? tEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToList()
                : new List<string>();
            var actions = root.TryGetProperty("actions", out var aEl) && aEl.ValueKind == JsonValueKind.Array
                ? aEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToList()
                : new List<string>();
            var trace = root.TryGetProperty("trace", out var trEl) && trEl.ValueKind == JsonValueKind.Array
                ? trEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToList()
                : new List<string>();

            return ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>.Ok((decision, triggered, actions, trace));
        }
        catch (Exception ex)
        {
            return ApiResult<(string Decision, List<string> TriggeredRules, List<string> Actions, List<string> Trace)>.Fail($"Failed to load data from 'api/v1/admin/policy/simulate'. {ex.Message}");
        }
    }

    public async Task<ApiResult<ReputationInsight>> GetIdentityInsightAsync(string identityId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(identityId))
        {
            return ApiResult<ReputationInsight>.Fail("Identity id is required.");
        }

        if (context.MockModeEnabled)
        {
            return ApiResult<ReputationInsight>.Ok(MockReputationInsight(identityId));
        }

        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>($"api/v1/plugins/identity/insights/{Uri.EscapeDataString(identityId)}", ct);
            var root = doc?.RootElement;
            if (root is null || root.Value.ValueKind != JsonValueKind.Object)
            {
                return ApiResult<ReputationInsight>.Fail($"Failed to load data from 'api/v1/plugins/identity/insights/{identityId}'. Empty response.");
            }

            var score = root.Value.TryGetProperty("reputationScore", out var sEl) && sEl.TryGetInt32(out var s) ? s : 0;
            var recentPolicy = root.Value.TryGetProperty("recentPolicy", out var rpEl) && rpEl.ValueKind == JsonValueKind.Array
                ? rpEl.EnumerateArray().ToList()
                : [];

            var blocked = recentPolicy.Count(x => x.TryGetProperty("outcome", out var outEl) && string.Equals(outEl.GetString(), "block", StringComparison.OrdinalIgnoreCase));
            var review = recentPolicy.Count(x => x.TryGetProperty("outcome", out var outEl) && string.Equals(outEl.GetString(), "review", StringComparison.OrdinalIgnoreCase));

            var reasons = new List<(string ReasonCode, int Count)>();
            if (root.Value.TryGetProperty("reasonBreakdown", out var rbEl) && rbEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var r in rbEl.EnumerateArray())
                {
                    var reason = r.TryGetProperty("reasonCode", out var rcEl) ? rcEl.GetString() ?? "none" : "none";
                    var count = r.TryGetProperty("count", out var cEl) && cEl.TryGetInt32(out var c) ? c : 0;
                    reasons.Add((reason, count));
                }
            }

            return ApiResult<ReputationInsight>.Ok(new ReputationInsight
            {
                IdentityId = identityId,
                ReputationScore = score,
                PolicyBlockCount = blocked,
                PolicyReviewCount = review,
                ReasonBreakdown = reasons
            });
        }
        catch (Exception ex)
        {
            return ApiResult<ReputationInsight>.Fail($"Failed to load data from 'api/v1/plugins/identity/insights/{identityId}'. {ex.Message}");
        }
    }

    public async Task<ApiResult<List<AuditLogEntry>>> GetAuditLogsAsync(CancellationToken ct = default)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<List<AuditLogEntry>>.Ok(MockLogs());
        }

        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>("api/v1/admin/audit?take=250", ct);
            var root = doc?.RootElement;
            if (root is null || root.Value.ValueKind != JsonValueKind.Array)
            {
                return ApiResult<List<AuditLogEntry>>.Ok(MockLogs());
            }

            var mapped = new List<AuditLogEntry>();
            foreach (var e in root.Value.EnumerateArray())
            {
                var created = e.TryGetProperty("createdAtUtc", out var createdEl) && createdEl.ValueKind == JsonValueKind.String
                    && DateTime.TryParse(createdEl.GetString(), out var dt)
                    ? dt
                    : DateTime.UtcNow;

                var subject = e.TryGetProperty("subject", out var subjectEl) ? subjectEl.GetString() ?? "unknown" : "unknown";
                var eventType = e.TryGetProperty("eventType", out var eventEl) ? eventEl.GetString() ?? "unknown" : "unknown";
                var category = e.TryGetProperty("category", out var catEl) ? catEl.GetString() ?? "general" : "general";
                var outcome = e.TryGetProperty("outcome", out var outEl) ? outEl.GetString() ?? "unknown" : "unknown";
                var reason = e.TryGetProperty("reasonCode", out var reasonEl) ? reasonEl.GetString() ?? string.Empty : string.Empty;
                var detail = e.TryGetProperty("detail", out var detailEl) ? detailEl.GetString() ?? string.Empty : string.Empty;

                var severity = outcome.Equals("success", StringComparison.OrdinalIgnoreCase)
                    ? "Info"
                    : outcome.Equals("review", StringComparison.OrdinalIgnoreCase)
                        ? "Warning"
                        : "Critical";

                mapped.Add(new AuditLogEntry
                {
                    Timestamp = created,
                    Actor = subject,
                    EventType = eventType,
                    Category = category,
                    Severity = severity,
                    Result = outcome,
                    Detail = string.IsNullOrWhiteSpace(reason) ? detail : $"{detail} ({reason})"
                });
            }

            return ApiResult<List<AuditLogEntry>>.Ok(mapped);
        }
        catch (Exception ex)
        {
            return ApiResult<List<AuditLogEntry>>.Fail($"Failed to load audit logs. {ex.Message}");
        }
    }

    public async Task<ApiResult<PolicyPackSummary>> GetPolicyPackSummaryAsync(CancellationToken ct = default)
    {
        // First real endpoint wiring: plugin metadata route from API service.
        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>("api/v1/plugins/policy/current", ct);
            var root = doc?.RootElement;
            if (root is not null && root.Value.TryGetProperty("policyVersion", out var policyVersion))
            {
                var source = root.Value.TryGetProperty("source", out var sourceEl) ? sourceEl.GetString() ?? "default" : "default";
                var summary = new PolicyPackSummary
                {
                    Name = source.Equals("strict", StringComparison.OrdinalIgnoreCase)
                        ? "HIP Strict Policy Pack"
                        : "HIP Default Policy Pack",
                    Version = policyVersion.GetString() ?? "unknown",
                    EnabledRules = root.Value.TryGetProperty("requiredScores", out var scores) ? scores.EnumerateObject().Count() : 0,
                    LastUpdatedUtc = DateTime.UtcNow
                };

                return ApiResult<PolicyPackSummary>.Ok(summary);
            }
        }
        catch
        {
            // fall through to mock fallback
        }

        return ApiResult<PolicyPackSummary>.Ok(MockPolicyPack());
    }

    public async Task<ApiResult<SystemUsageSummary>> GetSystemUsageSummaryAsync(CancellationToken ct = default)
    {
        // First real endpoint wiring: system metrics plugin route.
        try
        {
            using var doc = await httpClient.GetFromJsonAsync<JsonDocument>("api/v1/plugins/system-metrics?take=1", ct);
            var root = doc?.RootElement;
            if (root is not null && root.Value.TryGetProperty("samples", out var samples) && samples.ValueKind == JsonValueKind.Array)
            {
                var first = samples.EnumerateArray().FirstOrDefault();
                if (first.ValueKind == JsonValueKind.Object)
                {
                    var cpu = first.TryGetProperty("cpu", out var cpuEl) ? cpuEl.GetDouble() : 0d;
                    var memPercent = first.TryGetProperty("memory", out var memEl) ? memEl.GetDouble() : 0d;
                    const double assumedTotalGb = 8.0;
                    var used = Math.Round((memPercent / 100d) * assumedTotalGb, 2);

                    var usage = new SystemUsageSummary
                    {
                        CpuPercent = cpu,
                        MemoryUsedGb = used,
                        MemoryTotalGb = assumedTotalGb,
                        DiskPercent = null,
                        SampledUtc = DateTime.UtcNow
                    };

                    return ApiResult<SystemUsageSummary>.Ok(usage);
                }
            }
        }
        catch
        {
            // fall through to mock fallback
        }

        return ApiResult<SystemUsageSummary>.Ok(MockSystemUsage());
    }

    private async Task<ApiResult<List<T>>> ExecuteWithMockFallback<T>(Func<Task<List<T>>> apiCall, List<T> mock, string endpoint)
    {
        if (context.MockModeEnabled)
        {
            return ApiResult<List<T>>.Ok(mock);
        }

        try
        {
            var data = await apiCall();
            return ApiResult<List<T>>.Ok(data ?? mock);
        }
        catch (Exception ex)
        {
            return context.MockModeEnabled
                ? ApiResult<List<T>>.Ok(mock)
                : ApiResult<List<T>>.Fail($"Failed to load data from '{endpoint}'. {ex.Message}");
        }
    }

    private async Task<JsonDocument?> GetJsonDocumentWithRetryAsync(string path, CancellationToken ct)
    {
        Exception? last = null;

        for (var attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                return await httpClient.GetFromJsonAsync<JsonDocument>(path, ct);
            }
            catch (Exception ex)
            {
                last = ex;
                if (!ex.Message.Contains("ResponseEnded", StringComparison.OrdinalIgnoreCase) || attempt == 2)
                {
                    throw;
                }

                await Task.Delay(120, ct);
            }
        }

        throw last ?? new InvalidOperationException($"Failed to load '{path}'.");
    }

    private static List<DashboardMetric> MockMetrics() =>
    [
        new() { Title = "Total Users", Value = "12,482", Delta = "+4.8%", Trend = "up" },
        new() { Title = "Risk Alerts", Value = "38", Delta = "-2.1%", Trend = "down" },
        new() { Title = "Policy Match", Value = "97.4%", Delta = "+0.3%", Trend = "up" },
        new() { Title = "Active Sessions", Value = "1,284", Delta = "+8.2%", Trend = "up" }
    ];

    private static List<ActivityItem> MockActivity() =>
    [
        new() { Timestamp = DateTime.UtcNow.AddMinutes(-12), Actor = "security.bot", Action = "Policy test completed" },
        new() { Timestamp = DateTime.UtcNow.AddMinutes(-25), Actor = "analyst@hip.local", Action = "Reviewed suspicious cluster" },
        new() { Timestamp = DateTime.UtcNow.AddHours(-1), Actor = "admin@hip.local", Action = "Updated MFA baseline" }
    ];

    private static List<SecurityCheck> MockSecurity() =>
    [
        new() { Name = "MFA Enforced", Status = "Healthy", LastChecked = DateTime.UtcNow.AddMinutes(-1) },
        new() { Name = "Token Hygiene", Status = "Warning", LastChecked = DateTime.UtcNow.AddMinutes(-1) },
        new() { Name = "Geo Velocity", Status = "Healthy", LastChecked = DateTime.UtcNow.AddMinutes(-1) },
        new() { Name = "Root Access Monitoring", Status = "Critical", LastChecked = DateTime.UtcNow.AddMinutes(-1) }
    ];

    private static List<UserDeviceRecord> MockUsers() =>
    [
        new() { User = "Nora Kim", Email = "nora@hip.local", Device = "MacBook Pro", DeviceStatus = "Compliant", LastSeen = DateTime.UtcNow.AddMinutes(-5) },
        new() { User = "Derek Holt", Email = "derek@hip.local", Device = "Pixel 9", DeviceStatus = "Pending", LastSeen = DateTime.UtcNow.AddMinutes(-18) },
        new() { User = "Mina Rao", Email = "mina@hip.local", Device = "Windows 11", DeviceStatus = "Blocked", LastSeen = DateTime.UtcNow.AddHours(-3) }
    ];

    private static List<PolicyRule> MockRules() =>
    [
        new() { RuleId = "POL-001", Name = "MFA Required for Admin Actions", Category = "Login", Condition = "mfa == false", Action = "Challenge", Severity = "Critical", Enabled = true },
        new() { RuleId = "POL-017", Name = "Block impossible travel login", Category = "Login", Condition = "geoJump < 2h", Action = "Block", Severity = "High", Enabled = true },
        new() { RuleId = "POL-033", Name = "Session renewal every 12h", Category = "Token", Condition = "sessionAge > 12h", Action = "Warn", Severity = "Medium", Enabled = false }
    ];

    private static PolicyPackSummary MockPolicyPack() => new()
    {
        Name = "HIP Core Policy Pack",
        Version = "2026.03.1",
        EnabledRules = 42,
        LastUpdatedUtc = DateTime.UtcNow.AddHours(-6)
    };

    private static SystemUsageSummary MockSystemUsage() => new()
    {
        CpuPercent = 27.4,
        MemoryUsedGb = 2.9,
        MemoryTotalGb = 7.8,
        DiskPercent = 61.0,
        SampledUtc = DateTime.UtcNow.AddSeconds(-20)
    };

    private static List<ReputationWatchItem> MockReputationWatch() =>
    [
        new() { IdentityId = "support@hip.local", Score = 52, Blocked = 1, Review = 3 },
        new() { IdentityId = "admin@hip.local", Score = 81, Blocked = 0, Review = 1 },
        new() { IdentityId = "guest@hip.local", Score = 34, Blocked = 3, Review = 2 }
    ];

    private static ReputationInsight MockReputationInsight(string identityId) => new()
    {
        IdentityId = identityId,
        ReputationScore = 82,
        PolicyBlockCount = 1,
        PolicyReviewCount = 2,
        ReasonBreakdown =
        [
            ("positive_feedback", 3),
            ("auth_failure", 2),
            ("low_abuse", 1)
        ]
    };

    private static List<AuditLogEntry> MockLogs() => Enumerable.Range(1, 48)
        .Select(i => new AuditLogEntry
        {
            Timestamp = DateTime.UtcNow.AddMinutes(i * -9),
            Actor = i % 2 == 0 ? "admin@hip.local" : "support@hip.local",
            Category = i % 3 == 0 ? "Policy" : "Session",
            EventType = i % 4 == 0 ? "PolicyTest" : i % 3 == 0 ? "TokenAction" : "LoginCheck",
            Severity = i % 9 == 0 ? "Critical" : i % 4 == 0 ? "Warning" : "Info",
            Result = i % 5 == 0 ? "Denied" : "Success",
            Detail = $"Action #{i} processed"
        })
        .ToList();
}
