using HIP.RateLimitGuard.Models;
using HIP.RateLimitGuard.Services;
using HIP.RateLimitGuard.Stores;

namespace HIP.RateLimitGuard.Tests;

public sealed class RateLimitGuardTests
{
    private static GuardRequest Request(
        string requestType = "chat",
        bool canFallback = false,
        int depth = 1,
        string fingerprint = "fp-1",
        string chainFingerprint = "chain-1",
        int compressed = 100)
        => new(
            AgentId: "ethan",
            RequestType: requestType,
            Priority: RequestPriority.Normal,
            RequiresApi: true,
            CanFallbackToLocal: canFallback,
            ParentRequestId: "parent-1",
            ConversationId: "conv-1",
            SessionId: "sess-1",
            Depth: depth,
            MaxWaitTolerance: TimeSpan.Zero,
            Source: RequestSource.Agent,
            NormalizedIntentVersion: "v1",
            Fingerprint: fingerprint,
            IdempotencyKey: Guid.NewGuid().ToString("N"),
            PromptSizeBeforeCompression: 200,
            PromptSizeAfterCompression: compressed,
            ChainFingerprint: chainFingerprint);

    private static RateLimitGuard.Services.RateLimitGuard Guard(RateLimitGuardOptions? options = null)
        => new(options ?? new RateLimitGuardOptions
        {
            RolloutMode = RolloutMode.EnforceBudgetsConstrainedEmergency,
            PerTypeCooldowns = new Dictionary<string, TimeSpan>(StringComparer.OrdinalIgnoreCase) { ["chat"] = TimeSpan.FromMinutes(1) },
            PerMinuteTokenBudget = 500,
            PerAgentBudgetLimit = 500,
            PerAgentBudgetWindow = TimeSpan.FromMinutes(1),
            ManualOnlyRequestTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "manual-task" }
        }, new InMemoryInflightStore(), new InMemoryBudgetStore(), new InMemoryCooldownStore(), new InMemoryCacheStore());

    [Test]
    public async Task Cooldown_BlocksSecondCall()
    {
        var guard = Guard();
        var first = Request(fingerprint: "cooldown-a");
        var second = Request(fingerprint: "cooldown-b");

        Assert.That((await guard.EvaluateAsync(first)).Action, Is.EqualTo(GuardAction.AllowNow));
        await guard.CompleteAsync(first, success: true, responsePayload: "ok");

        var decision = await guard.EvaluateAsync(second);
        Assert.That(decision.ReasonCode, Is.EqualTo(GuardReasonCode.CooldownActive));
    }

    [Test]
    public async Task Dedupe_UsesInflightReuse()
    {
        var guard = Guard();
        var first = Request(fingerprint: "same-fp");
        var second = Request(fingerprint: "same-fp");

        Assert.That((await guard.EvaluateAsync(first)).Action, Is.EqualTo(GuardAction.AllowNow));
        var dedupe = await guard.EvaluateAsync(second);
        Assert.That(dedupe.Action, Is.EqualTo(GuardAction.DedupeReuse));
    }

    [Test]
    public async Task BudgetExhaustion_Blocks()
    {
        var guard = Guard();
        var big = Request(fingerprint: "budget-a", compressed: 480);
        var next = Request(fingerprint: "budget-b", compressed: 100);

        Assert.That((await guard.EvaluateAsync(big)).Action, Is.EqualTo(GuardAction.AllowNow));
        var blocked = await guard.EvaluateAsync(next);
        Assert.That(blocked.ReasonCode, Is.EqualTo(GuardReasonCode.BudgetExceeded));
    }

    [Test]
    public async Task CircuitBreaker_OpensAfterFailures()
    {
        var guard = Guard(new RateLimitGuardOptions
        {
            RolloutMode = RolloutMode.EnforceBudgetsConstrainedEmergency,
            CircuitBreaker = new CircuitBreakerOptions(FailureThreshold: 2, OpenDuration: TimeSpan.FromMinutes(1)),
            PerTypeCooldowns = new(),
            ManualOnlyRequestTypes = new()
        });

        var a = Request();
        var b = Request(fingerprint: "fp-2");
        await guard.EvaluateAsync(a);
        await guard.CompleteAsync(a, success: false);
        await guard.EvaluateAsync(b);
        await guard.CompleteAsync(b, success: false);

        var c = await guard.EvaluateAsync(Request(fingerprint: "fp-3", canFallback: true));
        Assert.That(c.ReasonCode, Is.EqualTo(GuardReasonCode.CircuitOpen));
    }

    [Test]
    public async Task ManualOnly_BlocksWithoutOverride()
    {
        var guard = Guard();
        var decision = await guard.EvaluateAsync(Request(requestType: "manual-task"));
        Assert.That(decision.ReasonCode, Is.EqualTo(GuardReasonCode.ManualOnly));
    }

    [Test]
    public async Task LocalFallback_ReturnsLocalOnly()
    {
        var guard = Guard();
        var first = Request(fingerprint: "fallback-a");
        await guard.EvaluateAsync(first);
        await guard.CompleteAsync(first, success: true, responsePayload: "ok");

        var fallback = await guard.EvaluateAsync(Request(canFallback: true, fingerprint: "fallback-b"));
        Assert.That(fallback.Action, Is.EqualTo(GuardAction.LocalOnly));
    }

    [Test]
    public async Task LoopDetection_BlocksUnsafeLoop()
    {
        var guard = Guard(new RateLimitGuardOptions
        {
            RolloutMode = RolloutMode.EnforceBudgetsConstrainedEmergency,
            MaxChainRepeat = 2,
            PerTypeCooldowns = new(),
            ManualOnlyRequestTypes = new()
        });

        await guard.EvaluateAsync(Request(chainFingerprint: "loop-x", fingerprint: "a"));
        await guard.EvaluateAsync(Request(chainFingerprint: "loop-x", fingerprint: "b"));
        var blocked = await guard.EvaluateAsync(Request(chainFingerprint: "loop-x", fingerprint: "c"));

        Assert.That(blocked.ReasonCode, Is.EqualTo(GuardReasonCode.UnsafeLoop));
    }
}
