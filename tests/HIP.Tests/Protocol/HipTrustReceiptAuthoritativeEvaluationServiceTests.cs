using FluentValidation;
using HIP.Application;
using HIP.Application.Protocol;
using HIP.Application.SiteSafety;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

/// <summary>Verifies signed receipts cannot treat browser-authored observations as authoritative evidence.</summary>
[TestFixture]
[NonParallelizable]
public sealed class HipTrustReceiptAuthoritativeEvaluationServiceTests
{
    /// <summary>
    /// Proves the dedicated receipt request carries only the URL supplied to the Site Safety scanner.
    /// </summary>
    [Test]
    public async Task Evaluate_uses_only_the_validated_url_and_strips_client_authored_evidence()
    {
        var expected = Evaluation();
        var scanner = new RecordingScanner(expected);
        var service = new HipTrustReceiptAuthoritativeEvaluationService(
            new SiteSafetyScanValidator(),
            scanner);
        var untrustedRequest = new HipTrustReceiptIssueRequest(
            "https://example.com/account?private=value");

        var actual = await service.EvaluateAsync(untrustedRequest, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(actual, Is.SameAs(expected));
            Assert.That(scanner.CallCount, Is.EqualTo(1));
            Assert.That(scanner.LastRequest, Is.EqualTo(new SiteSafetyScanRequest(untrustedRequest.Url)));
            Assert.That(scanner.LastRequest!.ObservedSignals, Is.Null);
            Assert.That(scanner.LastRequest.PluginVersion, Is.Null);
        });
    }

    /// <summary>Proves the target URL is rejected before the scanner can perform any work.</summary>
    [Test]
    public void Evaluate_rejects_an_unsafe_url_before_invoking_the_scanner()
    {
        var scanner = new RecordingScanner(Evaluation());
        var service = new HipTrustReceiptAuthoritativeEvaluationService(
            new SiteSafetyScanValidator(),
            scanner);

        Assert.ThrowsAsync<ValidationException>(() => service.EvaluateAsync(
            new HipTrustReceiptIssueRequest("http://127.0.0.1/private"),
            CancellationToken.None));
        Assert.That(scanner.CallCount, Is.Zero);
    }

    /// <summary>Locks the authoritative evaluation boundary into the normal application service graph.</summary>
    [Test]
    public void Application_registration_exposes_the_authoritative_evaluation_boundary_as_scoped()
    {
        var services = new ServiceCollection();

        services.AddHipApplication();

        var registration = services.Single(descriptor =>
            descriptor.ServiceType == typeof(IHipTrustReceiptAuthoritativeEvaluationService));
        Assert.Multiple(() =>
        {
            Assert.That(registration.ImplementationType,
                Is.EqualTo(typeof(HipTrustReceiptAuthoritativeEvaluationService)));
            Assert.That(registration.Lifetime, Is.EqualTo(ServiceLifetime.Scoped));
        });
    }

    private static SiteSafetyScanResult Evaluation() => new(
        "site-safety-authoritative-test",
        "https://example.com/",
        "example.com",
        new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        SiteSafetyScanStatus.LimitedData,
        "Limited server evidence.",
        [],
        [],
        [],
        [],
        "Low",
        58,
        58,
        58,
        58,
        [],
        new SiteSafetyScoreImpact(58, 58, 58, 58, []),
        []);

    private sealed class RecordingScanner(SiteSafetyScanResult result) : ISiteSafetyScanner
    {
        public int CallCount { get; private set; }

        public SiteSafetyScanRequest? LastRequest { get; private set; }

        public Task<SiteSafetyScanResult> ScanAsync(
            SiteSafetyScanRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            LastRequest = request;
            return Task.FromResult(result);
        }
    }
}
