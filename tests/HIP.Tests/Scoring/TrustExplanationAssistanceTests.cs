using HIP.Application.Explanations;
using HIP.Domain.Risk;

namespace HIP.Tests.Scoring;

public sealed class TrustExplanationAssistanceTests
{
    [Test]
    public async Task Provider_receives_only_bounded_structured_score_facts()
    {
        var provider = new CapturingProvider(new("The score is lower because dangerous-link evidence was present.", "test-provider"));
        var assistant = new TrustExplanationAssistant(provider);
        var request = Request();

        var result = await assistant.TryExplainAsync(request, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.Not.Null);
            Assert.That(provider.Request, Is.EqualTo(request));
            Assert.That(typeof(TrustExplanationRequest).GetProperties().Select(property => property.Name),
                Does.Not.Contain("Domain").And.Not.Contain("Url").And.Not.Contain("PageText").And.Not.Contain("UserId"));
        });
    }

    [Test]
    public async Task Provider_failure_returns_no_assistance_instead_of_changing_hip_result()
    {
        var assistant = new TrustExplanationAssistant(new ThrowingProvider());
        Assert.That(await assistant.TryExplainAsync(Request(), CancellationToken.None), Is.Null);
    }

    [TestCase("Visit https://secret.example for details.")]
    [TestCase("bad\ncontrol")]
    public async Task Unsafe_provider_output_is_rejected(string explanation)
    {
        var assistant = new TrustExplanationAssistant(new CapturingProvider(new(explanation, "test-provider")));
        Assert.That(await assistant.TryExplainAsync(Request(), CancellationToken.None), Is.Null);
    }

    [Test]
    public void Free_form_or_oversized_signal_codes_are_rejected_before_provider_call()
    {
        var assistant = new TrustExplanationAssistant(new CapturingProvider(null));
        var request = Request() with { SignalCodes = ["raw private message"] };
        Assert.ThrowsAsync<ArgumentException>(() => assistant.TryExplainAsync(request, CancellationToken.None));
    }

    private static TrustExplanationRequest Request() =>
        new(42, 70, 45, 80, RiskStatus.HighRisk, ["dangerous-links", "status-highrisk"]);

    private sealed class CapturingProvider(TrustExplanationProviderResult? result) : ITrustExplanationProvider
    {
        public TrustExplanationRequest? Request { get; private set; }
        public Task<TrustExplanationProviderResult?> ExplainAsync(TrustExplanationRequest request, CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(result);
        }
    }

    private sealed class ThrowingProvider : ITrustExplanationProvider
    {
        public Task<TrustExplanationProviderResult?> ExplainAsync(TrustExplanationRequest request, CancellationToken cancellationToken) =>
            throw new TimeoutException("provider unavailable");
    }
}
