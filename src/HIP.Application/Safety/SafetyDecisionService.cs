using HIP.Application.Reporting;
using HIP.Domain.Risk;
using HIP.Domain.Safety;

namespace HIP.Application.Safety;

public enum SafetyDecisionAction
{
    GoBack = 1,
    Continue,
    ReportSafe,
    ReportDangerous
}

public enum SafetyDecisionStatus
{
    Unspecified = 0,
    Recorded,
    AdditionalConfirmationRequired,
    BlockedByPolicy,
    InvalidRequest,
    StorageUnavailable
}

/// <summary>Untrusted request; raw URL exists only long enough to evaluate and hash it.</summary>
public sealed record SafetyDecisionRequest(
    string Url,
    string? Source,
    SafetyDecisionAction Action,
    bool DangerAcknowledged);

/// <summary>Privacy-safe persisted decision. It intentionally contains no URL, path, query, fragment, or user ID.</summary>
public sealed record SafetyDecisionRecord(
    string DecisionId,
    string UrlHash,
    string DomainHash,
    string Source,
    SafetyDecisionAction Action,
    RiskStatus RiskLevel,
    DateTimeOffset RecordedAtUtc);

public sealed record SafetyDecisionResult(
    SafetyDecisionStatus Status,
    string? DecisionId = null,
    SafetyDecisionAction? Action = null,
    RiskStatus? RiskLevel = null,
    DateTimeOffset? RecordedAtUtc = null)
{
    public bool IsRecorded => Status == SafetyDecisionStatus.Recorded;
}

public interface ISafetyDecisionRepository
{
    Task AddAsync(SafetyDecisionRecord record, CancellationToken cancellationToken);
}

public interface ISafetyDecisionService
{
    Task<SafetyDecisionResult> RecordAsync(
        SafetyDecisionRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Bounded process-local repository used until durable portal decision storage is configured.</summary>
public sealed class InMemorySafetyDecisionRepository : ISafetyDecisionRepository
{
    private const int MaximumRecords = 10_000;
    private readonly object gate = new();
    private readonly Queue<SafetyDecisionRecord> records = new();

    public IReadOnlyCollection<SafetyDecisionRecord> Records
    {
        get
        {
            lock (gate)
            {
                return records.ToArray();
            }
        }
    }

    public Task AddAsync(SafetyDecisionRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            while (records.Count >= MaximumRecords)
            {
                records.Dequeue();
            }

            records.Enqueue(record);
        }

        return Task.CompletedTask;
    }
}

/// <summary>Re-evaluates policy server-side and stores only keyed hashes plus bounded decision metadata.</summary>
public sealed class SafetyDecisionService(
    ISafetyRoutingService safetyRoutingService,
    ISafetyDecisionRepository decisionRepository,
    IPrivacyHashingService privacyHashingService,
    TimeProvider timeProvider) : ISafetyDecisionService
{
    private readonly ISafetyRoutingService routing =
        safetyRoutingService ?? throw new ArgumentNullException(nameof(safetyRoutingService));
    private readonly ISafetyDecisionRepository repository =
        decisionRepository ?? throw new ArgumentNullException(nameof(decisionRepository));
    private readonly IPrivacyHashingService privacyHasher =
        privacyHashingService ?? throw new ArgumentNullException(nameof(privacyHashingService));
    private readonly TimeProvider clock = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public async Task<SafetyDecisionResult> RecordAsync(
        SafetyDecisionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(request.Action))
        {
            return new SafetyDecisionResult(SafetyDecisionStatus.InvalidRequest);
        }

        SafetyResult evaluation;
        Uri parsed;
        try
        {
            evaluation = routing.EvaluateUrl(request.Url, request.Source);
            parsed = new Uri(evaluation.OriginalUrl, UriKind.Absolute);
        }
        catch (ArgumentException)
        {
            return new SafetyDecisionResult(SafetyDecisionStatus.InvalidRequest);
        }

        if (request.Action == SafetyDecisionAction.Continue)
        {
            if (!evaluation.AllowContinue ||
                evaluation.ContinuationRequirement == SafetyContinuationRequirement.Blocked)
            {
                return new SafetyDecisionResult(
                    SafetyDecisionStatus.BlockedByPolicy,
                    Action: request.Action,
                    RiskLevel: evaluation.RiskLevel);
            }

            if (evaluation.ContinuationRequirement == SafetyContinuationRequirement.ExtraConfirmation &&
                !request.DangerAcknowledged)
            {
                return new SafetyDecisionResult(
                    SafetyDecisionStatus.AdditionalConfirmationRequired,
                    Action: request.Action,
                    RiskLevel: evaluation.RiskLevel);
            }
        }

        var recordedAtUtc = ProtocolTimestamp(clock.GetUtcNow());
        var record = new SafetyDecisionRecord(
            $"safety-decision:{Guid.NewGuid():N}",
            privacyHasher.Hash(evaluation.OriginalUrl),
            privacyHasher.Hash(parsed.IdnHost),
            NormalizeSource(request.Source),
            request.Action,
            evaluation.RiskLevel,
            recordedAtUtc);

        try
        {
            await repository.AddAsync(record, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return new SafetyDecisionResult(
                SafetyDecisionStatus.StorageUnavailable,
                Action: request.Action,
                RiskLevel: evaluation.RiskLevel);
        }

        return new SafetyDecisionResult(
            SafetyDecisionStatus.Recorded,
            record.DecisionId,
            record.Action,
            record.RiskLevel,
            record.RecordedAtUtc);
    }

    private static string NormalizeSource(string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return "unknown";
        }

        var normalized = source.Trim().ToLowerInvariant();
        return normalized.Length <= 64 && normalized.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.')
            ? normalized
            : "unknown";
    }

    private static DateTimeOffset ProtocolTimestamp(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(
            utc.Ticks - (utc.Ticks % TimeSpan.TicksPerMillisecond),
            TimeSpan.Zero);
    }
}
