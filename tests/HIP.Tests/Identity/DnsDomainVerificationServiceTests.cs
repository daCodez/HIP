using HIP.Application.Identity;
using HIP.Domain.Identity;
using Microsoft.Extensions.Logging;

namespace HIP.Tests.Identity;

/// <summary>
/// Tests DNS TXT domain verification without requiring live DNS or Docker.
/// </summary>
public sealed class DnsDomainVerificationServiceTests
{
    /// <summary>
    /// Verifies that an exact HIP TXT value proves domain control for the requested token.
    /// </summary>
    [Test]
    public async Task CheckDnsTxtAsync_returns_verified_when_record_matches_expected_token()
    {
        var service = Service(["hip-site-verification=good-token"]);

        var result = await service.CheckDnsTxtAsync("good.test", "good-token", CancellationToken.None);

        Assert.That(result.Domain, Is.EqualTo("good.test"));
        Assert.That(result.RecordName, Is.EqualTo("_hip.good.test"));
        Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.Verified));
    }

    /// <summary>
    /// Verifies that missing TXT evidence is reported as NotConfigured instead of being treated as failure or trust.
    /// </summary>
    [Test]
    public async Task CheckDnsTxtAsync_returns_not_configured_when_record_is_missing()
    {
        var service = Service([]);

        var result = await service.CheckDnsTxtAsync("missing.test", "good-token", CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.NotConfigured));
    }

    /// <summary>
    /// Verifies that a HIP TXT record with the wrong token is invalid.
    /// </summary>
    [Test]
    public async Task CheckDnsTxtAsync_returns_invalid_when_token_does_not_match()
    {
        var service = Service(["hip-site-verification=wrong-token"]);

        var result = await service.CheckDnsTxtAsync("bad.test", "good-token", CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.Invalid));
    }

    /// <summary>
    /// Verifies that invalid domains are rejected before DNS resolution.
    /// </summary>
    [Test]
    public void CheckDnsTxtAsync_rejects_invalid_domain_input()
    {
        var service = Service([]);

        var exception = Assert.ThrowsAsync<ArgumentException>(() =>
            service.CheckDnsTxtAsync("not a domain", "good-token", CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("Domain"));
    }

    /// <summary>
    /// Verifies that empty expected tokens are rejected before DNS resolution.
    /// </summary>
    [Test]
    public void CheckDnsTxtAsync_rejects_empty_expected_token()
    {
        var service = Service([]);

        var exception = Assert.ThrowsAsync<ArgumentException>(() =>
            service.CheckDnsTxtAsync("good.test", "", CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("Expected verification token"));
    }

    /// <summary>
    /// Verifies that DNS failures are safe pending states, not process crashes.
    /// </summary>
    [Test]
    public async Task CheckDnsTxtAsync_returns_pending_when_dns_resolution_fails()
    {
        var service = Service(_ => throw new InvalidOperationException("DNS unavailable"));

        var result = await service.CheckDnsTxtAsync("pending.test", "good-token", CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(DomainVerificationCheckStatus.PendingVerification));
    }

    /// <summary>
    /// Verifies that the expected token is not logged when DNS resolution fails.
    /// </summary>
    [Test]
    public async Task CheckDnsTxtAsync_does_not_log_expected_token_on_dns_failure()
    {
        var logger = new CapturingLogger<DnsDomainVerificationService>();
        var service = Service(_ => throw new InvalidOperationException("DNS unavailable"), logger);

        await service.CheckDnsTxtAsync("pending.test", "secret-token", CancellationToken.None);

        Assert.That(logger.Messages.Any(message => message.Contains("secret-token", StringComparison.Ordinal)), Is.False);
    }

    /// <summary>
    /// Verifies that DNS TXT verification updates a stored challenge to Verified when the record matches.
    /// </summary>
    [Test]
    public async Task VerifyAsync_marks_dns_challenge_verified_when_record_matches()
    {
        var service = Service(["hip-site-verification=good-token"]);
        await service.StartAsync("good.test", VerificationMethod.DnsTxt, CancellationToken.None);

        var result = await service.VerifyAsync("good.test", VerificationMethod.DnsTxt, "good-token", CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(VerificationStatus.Verified));
    }

    /// <summary>
    /// Creates a DNS verification service backed by static TXT records.
    /// </summary>
    /// <param name="records">TXT records returned by the fake resolver.</param>
    /// <returns>DNS verification service under test.</returns>
    private static DnsDomainVerificationService Service(IReadOnlyCollection<string> records) =>
        Service(_ => Task.FromResult(records));

    /// <summary>
    /// Creates a DNS verification service backed by a custom fake resolver callback.
    /// </summary>
    /// <param name="resolve">Callback used by the fake resolver.</param>
    /// <param name="logger">Optional capturing logger.</param>
    /// <returns>DNS verification service under test.</returns>
    private static DnsDomainVerificationService Service(
        Func<string, Task<IReadOnlyCollection<string>>> resolve,
        CapturingLogger<DnsDomainVerificationService>? logger = null) =>
        new(new StubDnsTxtRecordResolver(resolve), logger ?? new CapturingLogger<DnsDomainVerificationService>());

    /// <summary>
    /// Fake DNS resolver used to isolate verification logic from live DNS.
    /// </summary>
    /// <param name="resolve">Callback that returns TXT records or throws DNS-like failures.</param>
    private sealed class StubDnsTxtRecordResolver(Func<string, Task<IReadOnlyCollection<string>>> resolve) : IDnsTxtRecordResolver
    {
        /// <summary>
        /// Returns fake TXT records for the requested DNS name.
        /// </summary>
        /// <param name="recordName">Record name being resolved.</param>
        /// <param name="cancellationToken">Token used to cancel the lookup.</param>
        /// <returns>Fake TXT records.</returns>
        public Task<IReadOnlyCollection<string>> ResolveTxtRecordsAsync(string recordName, CancellationToken cancellationToken) =>
            resolve(recordName);
    }

    /// <summary>
    /// Minimal logger that captures formatted messages for token-leakage assertions.
    /// </summary>
    /// <typeparam name="T">Logged category type.</typeparam>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        /// <summary>
        /// Gets formatted log messages captured during a test.
        /// </summary>
        public List<string> Messages { get; } = [];

        /// <summary>
        /// Creates a no-op logging scope.
        /// </summary>
        /// <typeparam name="TState">Scope state type.</typeparam>
        /// <param name="state">Scope state.</param>
        /// <returns>No-op disposable scope.</returns>
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NoOpScope.Instance;

        /// <summary>
        /// Enables all log levels for the test logger.
        /// </summary>
        /// <param name="logLevel">Log level being checked.</param>
        /// <returns>Always true.</returns>
        public bool IsEnabled(LogLevel logLevel) => true;

        /// <summary>
        /// Captures formatted log messages without inspecting structured state internals.
        /// </summary>
        /// <typeparam name="TState">Log state type.</typeparam>
        /// <param name="logLevel">Log level.</param>
        /// <param name="eventId">Event identifier.</param>
        /// <param name="state">Log state.</param>
        /// <param name="exception">Logged exception.</param>
        /// <param name="formatter">Message formatter.</param>
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }
    }

    /// <summary>
    /// No-op disposable scope for the capturing logger.
    /// </summary>
    private sealed class NoOpScope : IDisposable
    {
        /// <summary>
        /// Gets the shared no-op scope.
        /// </summary>
        public static readonly NoOpScope Instance = new();

        /// <summary>
        /// Disposes the no-op scope.
        /// </summary>
        public void Dispose()
        {
        }
    }
}
