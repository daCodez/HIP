namespace HIP.Application.Consumer;

public interface IConsumerPortalService
{
    Task<ConsumerStatus> GetStatusAsync(string consumerId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ConsumerScanHistoryItem>> GetScansAsync(string consumerId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ConsumerReportHistoryItem>> GetReportsAsync(string consumerId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ConsumerAppealItem>> GetAppealsAsync(string consumerId, CancellationToken cancellationToken);

    ConsumerAppealSubmissionResult SubmitAppeal(string consumerId, ConsumerAppealSubmissionRequest request);

    Task<ConsumerSettings> GetSettingsAsync(string consumerId, CancellationToken cancellationToken);

    Task<ConsumerSettingsSaveResult> SaveSettingsAsync(
        string consumerId,
        ConsumerSettings settings,
        CancellationToken cancellationToken);
}
