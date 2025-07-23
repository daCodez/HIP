
namespace HIP.Reputation
{
 
    public interface IReputationService
    {
        Task<double> GetReputationAsync(string senderId);
        Task UpdateReputationAsync(string senderId, bool isPositiveInteraction);
    }

}