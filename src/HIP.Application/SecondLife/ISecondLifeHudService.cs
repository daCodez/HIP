namespace HIP.Application.SecondLife;

public interface ISecondLifeHudService
{
    SecondLifeHudActivationResponse Activate(SecondLifeHudActivationRequest request);

    SecondLifeHudScanResponse Scan(SecondLifeHudScanRequest request);

    SecondLifeHudSettings GetSettings(string deviceId);

    SecondLifeHudSettingsResponse SaveSettings(string deviceId, SecondLifeHudSettings settings);

    Task<SecondLifeHudFindingResponse> ReportFindingAsync(SecondLifeHudFindingReport report, CancellationToken cancellationToken);
}
