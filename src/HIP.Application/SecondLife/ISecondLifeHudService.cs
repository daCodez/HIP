namespace HIP.Application.SecondLife;

public interface ISecondLifeHudService
{
    SecondLifeHudActivationResponse Activate(SecondLifeHudActivationRequest request);

    Task<SecondLifeHudFindingResponse> ReportFindingAsync(SecondLifeHudFindingReport report, CancellationToken cancellationToken);
}
