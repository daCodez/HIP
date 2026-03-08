using System.Text;
using System.Text.Json;
using HIP.Protocol.Canonicalization;
using HIP.Protocol.Contracts;
using HIP.Protocol.Security.Abstractions;
using HIP.Protocol.Security.Services;
using HIP.Simulator.Core.Interfaces;
using HIP.Simulator.Core.Models;
using Microsoft.Extensions.Logging;

namespace HIP.Simulator.Core.Services;

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public sealed class JsonScenarioLoader(ILogger<JsonScenarioLoader> logger) : IScenarioLoader
{
    public async Task<IReadOnlyList<Scenario>> LoadAsync(string rootFolder, string? suite, string? scenarioId, CancellationToken ct = default)
    {
        var folder = Path.GetFullPath(rootFolder);
        if (!Directory.Exists(folder))
        {
            throw new DirectoryNotFoundException($"Scenario folder not found: {folder}");
        }

        var files = Directory.GetFiles(folder, "*.json", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".schema.json", StringComparison.OrdinalIgnoreCase)
                     && !f.EndsWith("threat-catalog.json", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        var scenarios = new List<Scenario>();
        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(folder, file).Replace('\\', '/');
            var detectedSuite = relative.Split('/').FirstOrDefault() ?? "default";
            if (!string.IsNullOrWhiteSpace(suite) && !detectedSuite.Equals(suite, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            await using var stream = File.OpenRead(file);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            var id = root.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? Path.GetFileNameWithoutExtension(file) : Path.GetFileNameWithoutExtension(file);
            if (!string.IsNullOrWhiteSpace(scenarioId) && !id.Equals(scenarioId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var expectedRules = root.TryGetProperty("expectedRules", out var erEl) && erEl.ValueKind == JsonValueKind.Array
                ? erEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray()
                : Array.Empty<string>();

            var expected = new ExpectedOutcome(
                expectedRules,
                root.TryGetProperty("expectedAction", out var eaEl) ? eaEl.GetString() ?? "LogOnly" : "LogOnly",
                root.TryGetProperty("expectedSeverity", out var esEl) ? esEl.GetString() ?? "Info" : "Info");

            var steps = new List<ScenarioStep>();
            if (root.TryGetProperty("steps", out var stepsEl) && stepsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var step in stepsEl.EnumerateArray())
                {
                    steps.Add(new ScenarioStep(
                        step.TryGetProperty("offsetSeconds", out var osEl) && osEl.TryGetInt32(out var os) ? os : 0,
                        step.TryGetProperty("eventType", out var etEl) ? etEl.GetString() ?? string.Empty : string.Empty,
                        step.TryGetProperty("actorId", out var aEl) ? aEl.GetString() ?? string.Empty : string.Empty,
                        step.TryGetProperty("targetId", out var tEl) ? tEl.GetString() : null,
                        step.TryGetProperty("payload", out var pEl) ? pEl.Clone() : default));
                }
            }

            var protocolSteps = ParseProtocolSteps(root);

            var tags = root.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array
                ? tagsEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray()
                : Array.Empty<string>();

            scenarios.Add(new Scenario(
                id,
                root.TryGetProperty("name", out var nEl) ? nEl.GetString() ?? id : id,
                root.TryGetProperty("description", out var dEl) ? dEl.GetString() ?? string.Empty : string.Empty,
                root.TryGetProperty("category", out var cEl) ? cEl.GetString() ?? detectedSuite : detectedSuite,
                tags,
                steps,
                protocolSteps,
                expected,
                root.TryGetProperty("shouldBeCovered", out var covEl) && covEl.ValueKind == JsonValueKind.True,
                !root.TryGetProperty("shouldBeValid", out var vEl) || vEl.ValueKind != JsonValueKind.False,
                ParseExecutionMode(root)));

        }

        logger.LogInformation("Loaded {Count} simulator scenarios from {Folder}", scenarios.Count, folder);
        return scenarios;
    }

    private static SimulationExecutionMode ParseExecutionMode(JsonElement root)
    {
        if (!root.TryGetProperty("executionMode", out var modeEl) || modeEl.ValueKind != JsonValueKind.String)
        {
            return SimulationExecutionMode.Application;
        }

        return modeEl.GetString()?.ToLowerInvariant() switch
        {
            "protocol" => SimulationExecutionMode.Protocol,
            "hybrid" => SimulationExecutionMode.Hybrid,
            _ => SimulationExecutionMode.Application
        };
    }

    private static IReadOnlyList<ProtocolScenarioStep> ParseProtocolSteps(JsonElement root)
    {
        if (!root.TryGetProperty("protocolSteps", out var psEl) || psEl.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<ProtocolScenarioStep>();
        }

        var steps = new List<ProtocolScenarioStep>();
        foreach (var step in psEl.EnumerateArray())
        {
            var rawType = step.TryGetProperty("stepType", out var stEl) ? stEl.GetString() : null;
            if (!Enum.TryParse<ProtocolStepType>(rawType, ignoreCase: true, out var type))
            {
                continue;
            }

            var expectSuccess = !step.TryGetProperty("expectSuccess", out var exEl) || exEl.ValueKind != JsonValueKind.False;
            var notes = step.TryGetProperty("notes", out var nEl) ? nEl.GetString() : null;
            steps.Add(new ProtocolScenarioStep(type, expectSuccess, notes));
        }

        return steps;
    }

    public Task<IReadOnlyList<string>> ListSuitesAsync(string rootFolder, CancellationToken ct = default)
    {
        var folder = Path.GetFullPath(rootFolder);
        var suites = Directory.Exists(folder)
            ? Directory.GetDirectories(folder).Select(Path.GetFileName).OfType<string>().Where(x => !string.IsNullOrWhiteSpace(x)).ToArray()
            : Array.Empty<string>();
        return Task.FromResult((IReadOnlyList<string>)suites);
    }

    public async Task<IReadOnlyList<(string Id, string Name, string Suite)>> ListScenariosAsync(string rootFolder, CancellationToken ct = default)
    {
        var scenarios = await LoadAsync(rootFolder, null, null, ct);
        return scenarios.Select(x => (x.Id, x.Name, x.Category)).ToArray();
    }
}

public sealed class ScenarioValidator : IScenarioValidator
{
    private static readonly HashSet<string> AllowedActions = ["Allow", "Kill", "Lock", "Block", "Quarantine", "Challenge", "RateLimit", "Warn", "Alert", "LogOnly"];
    private static readonly HashSet<string> AllowedSeverity = ["Info", "Warning", "Medium", "High", "Critical"];

    public IReadOnlyList<string> Validate(Scenario scenario)
    {
        var issues = new List<string>();
        if (string.IsNullOrWhiteSpace(scenario.Id)) issues.Add("id is required");
        if (string.IsNullOrWhiteSpace(scenario.Name)) issues.Add("name is required");

        if (scenario.ExecutionMode is SimulationExecutionMode.Application && scenario.Steps.Count == 0)
            issues.Add("application mode requires at least one event step");
        if (scenario.ExecutionMode is SimulationExecutionMode.Protocol && scenario.ProtocolSteps.Count == 0)
            issues.Add("protocol mode requires at least one protocolSteps entry");
        if (scenario.ExecutionMode is SimulationExecutionMode.Hybrid && (scenario.Steps.Count == 0 || scenario.ProtocolSteps.Count == 0))
            issues.Add("hybrid mode requires both event steps and protocolSteps");

        for (var i = 0; i < scenario.Steps.Count; i++)
        {
            var step = scenario.Steps[i];
            if (step.OffsetSeconds < 0) issues.Add($"steps[{i}].offsetSeconds must be >= 0");
            if (string.IsNullOrWhiteSpace(step.EventType)) issues.Add($"steps[{i}].eventType is required");
            if (string.IsNullOrWhiteSpace(step.ActorId)) issues.Add($"steps[{i}].actorId is required");
            if (step.Payload.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) issues.Add($"steps[{i}].payload is required");
        }

        if (!AllowedActions.Contains(scenario.ExpectedOutcome.ExpectedAction)) issues.Add("expectedAction is not supported");
        if (!AllowedSeverity.Contains(scenario.ExpectedOutcome.ExpectedSeverity)) issues.Add("expectedSeverity is not supported");

        return issues;
    }
}

public sealed class EventGenerator : IEventGenerator
{
    public IReadOnlyList<SecurityEvent> Generate(Scenario scenario, DateTimeOffset startedUtc)
        => scenario.Steps
            .OrderBy(x => x.OffsetSeconds)
            .Select(x => new SecurityEvent(x.EventType, x.ActorId, x.TargetId, startedUtc.AddSeconds(x.OffsetSeconds), x.Payload))
            .ToArray();
}

public sealed class InMemoryEventInjector : IEventInjector
{
    private readonly List<SecurityEvent> _events = [];
    public Task InjectAsync(SecurityEvent securityEvent, CancellationToken ct = default)
    {
        _events.Add(securityEvent);
        return Task.CompletedTask;
    }

    public IReadOnlyList<SecurityEvent> Events => _events;
}

public sealed class HipPolicyEvaluatorAdapter(ILogger<HipPolicyEvaluatorAdapter> logger) : IPolicyEvaluator
{
    public Task<PolicyEvaluationResult> EvaluateAsync(Scenario scenario, IReadOnlyList<SecurityEvent> events, SimulationRunOptions options, CancellationToken ct = default)
    {
        var traces = new List<RuleTraceEntry>();
        var matched = new List<(string Rule, string Action, string Severity, string Reason)>();
        var sideEffects = new List<string>();

        foreach (var e in events)
        {
            var p = e.Payload;
            Check("Require MFA", Bool(p, "mfa") == false && e.EventType.Contains("login", StringComparison.OrdinalIgnoreCase), "Challenge", "High", "MFA required", traces, matched);
            Check("Untrusted device challenge", Bool(p, "deviceTrusted") == false, "Challenge", "Medium", "Device not trusted", traces, matched);
            Check("Replay attempt block", Bool(p, "replayDetected") == true, "Block", "Critical", "Replay detected", traces, matched);
            Check("Token expiration block", Bool(p, "tokenExpired") == true, "Block", "High", "Token expired", traces, matched);
            Check("Low reputation restriction", Has(p, "reputation") && Int(p, "reputation") is < 30 and >= 10, "RateLimit", "Medium", "Low reputation", traces, matched);
            Check("Very low reputation quarantine", Has(p, "reputation") && Int(p, "reputation") < 10, "Quarantine", "Critical", "Very low reputation", traces, matched);
            Check("Phishing domain block", Bool(p, "domainFlagged") == true, "Block", "Critical", "Phishing domain", traces, matched);
            Check("Spam rate limit", Has(p, "messageRatePerMinute") && Int(p, "messageRatePerMinute") > 50, "RateLimit", "High", "Spam burst", traces, matched);
            Check("Suspicious IP alert", Str(p, "ipRisk").Equals("high", StringComparison.OrdinalIgnoreCase), "Alert", "Medium", "High IP risk", traces, matched);
            Check("Impossible travel block", Bool(p, "impossibleTravel") == true, "Block", "Critical", "Impossible travel", traces, matched);
            Check("Suspicious IP challenge", Str(p, "ipRisk").Equals("medium", StringComparison.OrdinalIgnoreCase), "Challenge", "Medium", "Medium IP risk", traces, matched);
            Check("Brute force lock", Int(p, "failedAttempts") >= 10, "Lock", "Critical", "Brute force threshold", traces, matched);
            Check("Session hijack detection", Bool(p, "sessionHijackSuspected") == true, "Kill", "Critical", "Hijack suspected", traces, matched);
        }

        if (matched.Count == 0)
        {
            logger.LogInformation("Uncovered event scenario detected: {ScenarioId}", scenario.Id);
            return Task.FromResult(new PolicyEvaluationResult("LogOnly", "Info", [], traces, sideEffects, false, "No policy rule matched any event step"));
        }

        var precedence = options.ActionPrecedence
            .Select((x, i) => (Action: x, Index: i))
            .ToDictionary(x => x.Action, x => x.Index, StringComparer.OrdinalIgnoreCase);

        var winner = matched
            .OrderBy(x => precedence.TryGetValue(x.Action, out var idx) ? idx : int.MaxValue)
            .First();

        sideEffects.Add($"Winning rule: {winner.Rule} due to precedence action={winner.Action}");

        return Task.FromResult(new PolicyEvaluationResult(
            winner.Action,
            winner.Severity,
            matched.Select(x => x.Rule).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            traces,
            sideEffects,
            true,
            null));
    }

    private static void Check(string rule, bool matched, string action, string severity, string reason, List<RuleTraceEntry> traces, List<(string Rule, string Action, string Severity, string Reason)> hits)
    {
        traces.Add(new RuleTraceEntry(rule, matched, action, severity, reason));
        if (matched) hits.Add((rule, action, severity, reason));
    }

    private static bool? Bool(JsonElement payload, string name)
        => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var el) && (el.ValueKind == JsonValueKind.True || el.ValueKind == JsonValueKind.False)
            ? el.GetBoolean()
            : null;

    private static int Int(JsonElement payload, string name)
        => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var n) ? n : 0;

    private static string Str(JsonElement payload, string name)
        => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var el) ? el.GetString() ?? string.Empty : string.Empty;

    private static bool Has(JsonElement payload, string name)
        => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out _);
}

public sealed class CoverageAnalyzer : ICoverageAnalyzer
{
    public CoverageReport Analyze(IReadOnlyList<Scenario> scenarios, IReadOnlyList<ScenarioResult> results)
    {
        var eventCoverage = results
            .SelectMany(r => scenarios.First(x => x.Id == r.ScenarioId).Steps.Select(s => (s.EventType, r.IsCovered, r.IsValid)))
            .GroupBy(x => x.EventType)
            .Select(g => new EventCoverageSummary(g.Key, g.Count(), g.Count(x => x.IsCovered), g.Count(x => !x.IsCovered && x.IsValid), g.Count(x => !x.IsValid)))
            .OrderBy(x => x.EventType)
            .ToArray();

        var ruleCoverage = results
            .SelectMany(r => r.RuleTrace)
            .GroupBy(x => x.RuleName)
            .Select(g => new RuleCoverageSummary(g.Key, g.Count(x => x.Matched), g.Count()))
            .OrderByDescending(x => x.MatchedCount)
            .ToArray();

        var fieldCoverage = scenarios
            .SelectMany(s => s.Steps)
            .SelectMany(step => step.Payload.ValueKind == JsonValueKind.Object ? step.Payload.EnumerateObject() : [])
            .GroupBy(x => x.Name)
            .Select(g => new FieldCoverageSummary(g.Key, g.Count(), g.Count(x => x.Value.ValueKind == JsonValueKind.Null || x.Value.ValueKind == JsonValueKind.Undefined)))
            .OrderByDescending(x => x.PresenceCount)
            .ToArray();

        return new CoverageReport(
            eventCoverage,
            ruleCoverage,
            fieldCoverage,
            results.Where(x => !x.IsCovered && x.IsValid).Select(x => x.ScenarioId).ToArray(),
            results.Where(x => !x.IsValid).Select(x => x.ScenarioId).ToArray(),
            results.Count(x => x.Suggestion is not null));
    }
}

public sealed class PolicySuggester : IPolicySuggester
{
    public PolicySuggestion Suggest(Scenario scenario, string gapReason)
    {
        var first = scenario.Steps.First();
        var signals = first.Payload.ValueKind == JsonValueKind.Object
            ? first.Payload.EnumerateObject().Select(x => x.Name).ToArray()
            : ["eventType", "actorId"];

        return new PolicySuggestion(
            RuleName: $"Sim.{scenario.Id}.Auto",
            Category: scenario.Category,
            ConditionExpression: $"eventType == '{first.EventType}'",
            RecommendedAction: "Challenge",
            RecommendedSeverity: "Medium",
            Reason: gapReason,
            NeededSignals: signals,
            PositiveTestCase: $"{first.EventType} with actor {first.ActorId}",
            NegativeTestCase: $"different event type than {first.EventType}",
            Notes: "Generated from uncovered simulator scenario. Review for false positives before enabling.");
    }
}

public sealed class JsonReportWriter(ILogger<JsonReportWriter> logger) : IReportWriter
{
    public async Task WriteAsync(SimulationRunResult result, SimulationRunOptions options, CancellationToken ct = default)
    {
        Directory.CreateDirectory(options.ReportFolder);
        var file = Path.Combine(options.ReportFolder, $"simulation-report-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
        await File.WriteAllTextAsync(file, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }), ct);
        logger.LogInformation("Wrote simulator JSON report: {File}", file);
    }
}

public sealed class HtmlReportWriter(ILogger<HtmlReportWriter> logger) : IReportWriter
{
    public async Task WriteAsync(SimulationRunResult result, SimulationRunOptions options, CancellationToken ct = default)
    {
        Directory.CreateDirectory(options.ReportFolder);
        var file = Path.Combine(options.ReportFolder, $"simulation-report-{DateTime.UtcNow:yyyyMMdd-HHmmss}.html");

        var rows = string.Join("\n", result.Scenarios.Select(s => $"<tr><td>{s.ScenarioId}</td><td>{s.Passed}</td><td>{s.IsCovered}</td><td>{s.IsValid}</td><td>{s.FinalAction}</td><td>{s.FinalSeverity}</td></tr>"));
        var html = $"<!doctype html><html><head><meta charset='utf-8'><title>HIP Simulator Report</title><style>body{{font-family:Arial,sans-serif;margin:20px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}</style></head><body><h1>HIP Simulator Report</h1><p>Total: {result.TotalScenarios} | Passed: {result.Passed} | Failed: {result.Failed} | Uncovered: {result.Uncovered} | Invalid: {result.Invalid} | Suggestions: {result.SuggestedPoliciesGenerated}</p><h2>Scenario Results</h2><table><tr><th>Scenario</th><th>Passed</th><th>Covered</th><th>Valid</th><th>Action</th><th>Severity</th></tr>{rows}</table></body></html>";

        await File.WriteAllTextAsync(file, html, ct);
        logger.LogInformation("Wrote simulator HTML report: {File}", file);
    }
}

public sealed class MarkdownSuggestionReportWriter(ILogger<MarkdownSuggestionReportWriter> logger) : IReportWriter
{
    public async Task WriteAsync(SimulationRunResult result, SimulationRunOptions options, CancellationToken ct = default)
    {
        Directory.CreateDirectory(options.ReportFolder);
        var file = Path.Combine(options.ReportFolder, $"simulation-suggestions-{DateTime.UtcNow:yyyyMMdd-HHmmss}.md");
        var lines = new List<string> { "# HIP Simulator Policy Suggestions", "" };
        foreach (var suggestion in result.Scenarios.Where(x => x.Suggestion is not null).Select(x => x.Suggestion!))
        {
            lines.Add(suggestion.ToTemplate());
            lines.Add("");
        }

        if (lines.Count == 2)
        {
            lines.Add("No suggestions generated.");
        }

        await File.WriteAllLinesAsync(file, lines, ct);
        logger.LogInformation("Wrote simulator markdown suggestions report: {File}", file);
    }
}

public sealed class ApplicationExecutionTarget(
    IScenarioValidator validator,
    IEventGenerator eventGenerator,
    IEventInjector eventInjector,
    IPolicyEvaluator evaluator,
    IPolicySuggester suggester,
    IClock clock) : ISimulationExecutionTarget
{
    public SimulationExecutionMode Mode => SimulationExecutionMode.Application;

    public async Task<ScenarioResult> ExecuteAsync(Scenario scenario, SimulationRunOptions options, CancellationToken ct = default)
    {
        var issues = validator.Validate(scenario);
        if (issues.Count > 0)
        {
            return new ScenarioResult(scenario.Id, false, false, false, "LogOnly", "Info", [], issues, [], [], SimulationExecutionMode.Application, null);
        }

        var events = eventGenerator.Generate(scenario, clock.UtcNow);
        foreach (var e in events)
        {
            await eventInjector.InjectAsync(e, ct);
        }

        var eval = await evaluator.EvaluateAsync(scenario, events, options, ct);
        var isPass = eval.IsCovered == scenario.ShouldBeCovered
                     && eval.FinalAction.Equals(scenario.ExpectedOutcome.ExpectedAction, StringComparison.OrdinalIgnoreCase)
                     && eval.FinalSeverity.Equals(scenario.ExpectedOutcome.ExpectedSeverity, StringComparison.OrdinalIgnoreCase)
                     && scenario.ExpectedOutcome.ExpectedRules.All(r => eval.MatchedRules.Contains(r, StringComparer.OrdinalIgnoreCase));

        var suggestion = !eval.IsCovered ? suggester.Suggest(scenario, eval.GapReason ?? "Coverage gap") : null;
        return new ScenarioResult(
            scenario.Id,
            isPass,
            eval.IsCovered,
            true,
            eval.FinalAction,
            eval.FinalSeverity,
            eval.MatchedRules,
            [],
            eval.RuleTrace,
            eval.SideEffects,
            SimulationExecutionMode.Application,
            suggestion);
    }
}

public sealed class ProtocolExecutionTarget(
    IScenarioValidator validator,
    IEventGenerator eventGenerator,
    IPolicySuggester suggester,
    HipEnvelopeSecurityService envelopeSecurity,
    HipReceiptSecurityService receiptSecurity,
    HipChallengeService challengeService,
    IHipSigner signer,
    IHipCanonicalSerializer canonical,
    IHipPayloadHasher hasher,
    IClock clock) : ISimulationExecutionTarget
{
    public SimulationExecutionMode Mode => SimulationExecutionMode.Protocol;

    public async Task<ScenarioResult> ExecuteAsync(Scenario scenario, SimulationRunOptions options, CancellationToken ct = default)
    {
        var issues = validator.Validate(scenario);
        if (issues.Count > 0)
        {
            return new ScenarioResult(scenario.Id, false, false, false, "LogOnly", "Info", [], issues, [], [], SimulationExecutionMode.Protocol, null);
        }

        var events = eventGenerator.Generate(scenario, clock.UtcNow);
        var first = events.FirstOrDefault() ?? new SecurityEvent(
            "protocol.synthetic",
            "sender-a",
            "receiver-b",
            clock.UtcNow,
            JsonDocument.Parse("{}").RootElement.Clone());

        var payloadText = first.Payload.GetRawText();
        var payloadHash = hasher.ComputePayloadHash(payloadText);

        var envelope = new HipMessageEnvelope(
            HipProtocolVersions.V1,
            first.EventType,
            first.ActorId,
            first.TargetId,
            first.TimestampUtc,
            Guid.NewGuid().ToString("N"),
            payloadHash,
            string.Empty,
            Guid.NewGuid().ToString("N"));

        var senderKeyId = "key-sender";
        var verifierKeyId = "hip-http-verifier";

        var signed = envelope with { Signature = SignEnvelope(envelope, senderKeyId) };

        HipVerificationOutcome verify = new(true);
        List<string> matchedRules = [];
        List<RuleTraceEntry> traces = [];

        var protocolSteps = scenario.ProtocolSteps.Count > 0
            ? scenario.ProtocolSteps
            : InferProtocolStepsFromPayload(first.Payload);

        HipTrustReceipt? receipt = null;
        HipChallenge? challenge = null;

        foreach (var step in protocolSteps)
        {
            switch (step.StepType)
            {
                case ProtocolStepType.SignEnvelope:
                    signed = signed with { Signature = SignEnvelope(signed, senderKeyId) };
                    matchedRules.Add("Protocol:SignEnvelope");
                    traces.Add(new RuleTraceEntry("Protocol:SignEnvelope", true, "Allow", "Info", "Envelope signed"));
                    break;

                case ProtocolStepType.VerifyEnvelope:
                    verify = await envelopeSecurity.VerifyAsync(signed, senderKeyId, ct);
                    matchedRules.Add("Protocol:EnvelopeVerify");
                    traces.Add(new RuleTraceEntry("Protocol:EnvelopeVerify", verify.Success == step.ExpectSuccess, verify.Success ? "Allow" : "Block", verify.Success ? "Info" : "High", verify.Error?.Message ?? "Envelope verify"));
                    break;

                case ProtocolStepType.ReplayAttempt:
                    _ = await envelopeSecurity.VerifyAsync(signed, senderKeyId, ct);
                    verify = await envelopeSecurity.VerifyAsync(signed, senderKeyId, ct);
                    matchedRules.Add("Protocol:ReplayGuard");
                    traces.Add(new RuleTraceEntry("Protocol:ReplayGuard", !verify.Success == step.ExpectSuccess, !verify.Success ? "Block" : "Allow", !verify.Success ? "Critical" : "Info", verify.Error?.Message ?? "Replay check"));
                    break;

                case ProtocolStepType.TimestampSkew:
                    var expired = signed with { TimestampUtc = clock.UtcNow.AddHours(-2), Nonce = Guid.NewGuid().ToString("N"), Signature = string.Empty };
                    var resigned = expired with { Signature = SignEnvelope(expired, senderKeyId) };
                    verify = await envelopeSecurity.VerifyAsync(resigned, senderKeyId, ct);
                    matchedRules.Add("Protocol:TimestampPolicy");
                    traces.Add(new RuleTraceEntry("Protocol:TimestampPolicy", !verify.Success == step.ExpectSuccess, !verify.Success ? "Block" : "Allow", !verify.Success ? "High" : "Info", verify.Error?.Message ?? "Timestamp check"));
                    break;

                case ProtocolStepType.IssueReceipt:
                    receipt = receiptSecurity.Issue(new HipTrustReceipt(
                        Guid.NewGuid().ToString("N"), HipProtocolVersions.V1, signed.MessageType, signed.SenderHipId, signed.ReceiverHipId,
                        clock.UtcNow, signed.PayloadHash, signed.DeviceId,
                        ["signature", "nonce", "timestamp", "payloadhash"], HipDecision.Allow, [], null, string.Empty), verifierKeyId);
                    matchedRules.Add("Protocol:ReceiptIssue");
                    traces.Add(new RuleTraceEntry("Protocol:ReceiptIssue", true, "Allow", "Info", "Receipt issued"));
                    break;

                case ProtocolStepType.VerifyReceipt:
                    receipt ??= receiptSecurity.Issue(new HipTrustReceipt(
                        Guid.NewGuid().ToString("N"), HipProtocolVersions.V1, signed.MessageType, signed.SenderHipId, signed.ReceiverHipId,
                        clock.UtcNow, signed.PayloadHash, signed.DeviceId,
                        ["signature", "nonce", "timestamp", "payloadhash"], HipDecision.Allow, [], null, string.Empty), verifierKeyId);
                    var receiptVerify = receiptSecurity.Verify(receipt, verifierKeyId);
                    matchedRules.Add("Protocol:ReceiptVerify");
                    traces.Add(new RuleTraceEntry("Protocol:ReceiptVerify", receiptVerify.Success == step.ExpectSuccess, receiptVerify.Success ? "Allow" : "Block", receiptVerify.Success ? "Info" : "High", receiptVerify.Error?.Message ?? "Receipt verify"));
                    break;

                case ProtocolStepType.ChallengeCreate:
                    challenge = challengeService.CreateChallenge(senderKeyId, verifierKeyId);
                    matchedRules.Add("Protocol:ChallengeCreate");
                    traces.Add(new RuleTraceEntry("Protocol:ChallengeCreate", true, "Allow", "Info", "Challenge created"));
                    break;

                case ProtocolStepType.ChallengeVerify:
                    challenge ??= challengeService.CreateChallenge(senderKeyId, verifierKeyId);
                    var proof = challengeService.CreateProof(challenge, senderKeyId, senderKeyId);
                    var proofOk = challengeService.VerifyProof(challenge, proof, senderKeyId);
                    matchedRules.Add("Protocol:ChallengeVerify");
                    traces.Add(new RuleTraceEntry("Protocol:ChallengeVerify", proofOk == step.ExpectSuccess, proofOk ? "Allow" : "Challenge", proofOk ? "Info" : "Medium", "Challenge round-trip"));
                    break;

                case ProtocolStepType.KeyRevoked:
                    verify = new HipVerificationOutcome(false, new HipError(HipErrorCode.KeyRevoked, "Key revoked (simulated)", signed.CorrelationId));
                    matchedRules.Add("Protocol:KeyRevoked");
                    traces.Add(new RuleTraceEntry("Protocol:KeyRevoked", step.ExpectSuccess == false, "Block", "Critical", "Revocation path simulated"));
                    break;

                case ProtocolStepType.KeyReplaced:
                    verify = new HipVerificationOutcome(false, new HipError(HipErrorCode.KeyRevoked, "Key replaced (simulated)", signed.CorrelationId, "replacement-key"));
                    matchedRules.Add("Protocol:KeyReplaced");
                    traces.Add(new RuleTraceEntry("Protocol:KeyReplaced", step.ExpectSuccess == false, "Block", "Critical", "Replacement path simulated"));
                    break;
            }
        }

        var (action, severity, covered, gap) = verify.Success
            ? ("Allow", "Info", true, (string?)null)
            : ToPolicyOutcome(verify.Error?.Code);

        var isPass = covered == scenario.ShouldBeCovered
                     && action.Equals(scenario.ExpectedOutcome.ExpectedAction, StringComparison.OrdinalIgnoreCase)
                     && severity.Equals(scenario.ExpectedOutcome.ExpectedSeverity, StringComparison.OrdinalIgnoreCase);

        var suggestion = !covered ? suggester.Suggest(scenario, gap ?? "Protocol coverage gap") : null;

        return new ScenarioResult(
            scenario.Id,
            isPass,
            covered,
            true,
            action,
            severity,
            matchedRules.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            [],
            traces,
            ["Executed against HIP.Protocol target"],
            SimulationExecutionMode.Protocol,
            suggestion);
    }

    private string SignEnvelope(HipMessageEnvelope envelope, string keyId)
    {
        var unsigned = envelope with { Signature = string.Empty };
        var canonicalPayload = canonical.CanonicalizeEnvelope(unsigned);
        return signer.Sign(canonicalPayload, keyId);
    }

    private static IReadOnlyList<ProtocolScenarioStep> InferProtocolStepsFromPayload(JsonElement payload)
    {
        if (payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty("replayDetected", out var replay) && replay.ValueKind == JsonValueKind.True)
            return [new ProtocolScenarioStep(ProtocolStepType.VerifyEnvelope), new ProtocolScenarioStep(ProtocolStepType.ReplayAttempt, ExpectSuccess: false)];

        if (payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty("tokenExpired", out var expired) && expired.ValueKind == JsonValueKind.True)
            return [new ProtocolScenarioStep(ProtocolStepType.TimestampSkew, ExpectSuccess: false)];

        return
        [
            new ProtocolScenarioStep(ProtocolStepType.SignEnvelope),
            new ProtocolScenarioStep(ProtocolStepType.VerifyEnvelope),
            new ProtocolScenarioStep(ProtocolStepType.IssueReceipt),
            new ProtocolScenarioStep(ProtocolStepType.VerifyReceipt),
            new ProtocolScenarioStep(ProtocolStepType.ChallengeCreate),
            new ProtocolScenarioStep(ProtocolStepType.ChallengeVerify)
        ];
    }

    private static (string Action, string Severity, bool Covered, string? GapReason) ToPolicyOutcome(HipErrorCode? code)
        => code switch
        {
            HipErrorCode.ReplayDetected => ("Block", "Critical", true, null),
            HipErrorCode.TimestampExpired => ("Block", "High", true, null),
            HipErrorCode.InvalidSignature => ("Block", "High", true, null),
            HipErrorCode.KeyRevoked => ("Block", "Critical", true, null),
            null => ("Block", "High", false, "Verification failed without explicit error code"),
            _ => ("Block", "High", false, $"Unhandled protocol error code: {code}")
        };
}

public sealed class SimulationRunner(
    IScenarioLoader loader,
    ICoverageAnalyzer coverage,
    IEnumerable<IReportWriter> writers,
    IEnumerable<ISimulationExecutionTarget> executionTargets,
    ILogger<SimulationRunner> logger) : ISimulationRunner
{
    public async Task<SimulationRunResult> RunAsync(SimulationRunOptions options, CancellationToken ct = default)
    {
        var scenarios = await loader.LoadAsync(options.InputFolder, options.Suite, options.ScenarioId, ct);
        var results = new List<ScenarioResult>();

        options.Progress?.Report(new SimulationProgressUpdate("loaded", 0, scenarios.Count, null, "Scenarios loaded"));

        var targetByMode = executionTargets.ToDictionary(x => x.Mode);

        for (var i = 0; i < scenarios.Count; i++)
        {
            var scenario = scenarios[i];
            ct.ThrowIfCancellationRequested();

            var effectiveMode = options.ExecutionModeOverride ?? scenario.ExecutionMode;
            if (effectiveMode is SimulationExecutionMode.Hybrid)
            {
                results.Add(new ScenarioResult(
                    scenario.Id,
                    false,
                    false,
                    false,
                    "LogOnly",
                    "Info",
                    [],
                    ["Hybrid execution mode is not implemented yet."],
                    [],
                    [],
                    SimulationExecutionMode.Hybrid,
                    null));

                options.Progress?.Report(new SimulationProgressUpdate("unsupported-mode", i + 1, scenarios.Count, scenario.Id, "Hybrid mode not yet implemented"));
                continue;
            }

            if (!targetByMode.TryGetValue(effectiveMode, out var target))
            {
                results.Add(new ScenarioResult(
                    scenario.Id,
                    false,
                    false,
                    false,
                    "LogOnly",
                    "Info",
                    [],
                    [$"No execution target registered for mode '{effectiveMode}'."],
                    [],
                    [],
                    effectiveMode,
                    null));

                options.Progress?.Report(new SimulationProgressUpdate("unsupported-mode", i + 1, scenarios.Count, scenario.Id, $"No target for mode '{effectiveMode}'"));
                continue;
            }

            options.Progress?.Report(new SimulationProgressUpdate("executing", i, scenarios.Count, scenario.Id, $"Executing scenario via {effectiveMode} target"));
            var result = await target.ExecuteAsync(scenario, options, ct);
            results.Add(result);
            options.Progress?.Report(new SimulationProgressUpdate("scenario-complete", i + 1, scenarios.Count, scenario.Id, result.Passed ? "Scenario passed" : "Scenario failed"));
        }

        options.Progress?.Report(new SimulationProgressUpdate("analyzing", scenarios.Count, scenarios.Count, null, "Computing coverage and summaries"));
        var runResult = new SimulationRunResult(
            TotalScenarios: results.Count,
            Passed: results.Count(x => x.Passed),
            Failed: results.Count(x => !x.Passed),
            Uncovered: results.Count(x => !x.IsCovered && x.IsValid),
            Invalid: results.Count(x => !x.IsValid),
            SuggestedPoliciesGenerated: results.Count(x => x.Suggestion is not null),
            Scenarios: results,
            Coverage: coverage.Analyze(scenarios, results));

        options.Progress?.Report(new SimulationProgressUpdate("writing-reports", scenarios.Count, scenarios.Count, null, "Writing reports"));
        foreach (var writer in writers)
        {
            await writer.WriteAsync(runResult, options, ct);
        }

        options.Progress?.Report(new SimulationProgressUpdate("completed", scenarios.Count, scenarios.Count, null, "Simulation run completed"));
        logger.LogInformation("Simulation run complete: Total={Total} Passed={Passed} Failed={Failed}", runResult.TotalScenarios, runResult.Passed, runResult.Failed);
        return runResult;
    }
}
