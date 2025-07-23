using System.Collections.Concurrent;

namespace HIP.Reputation
{
    public class ReputationService : IReputationService
    {
        private readonly ConcurrentDictionary<string, double> _reputationStore = new();

        public Task<double> GetReputationAsync(string senderId)
        {
            _reputationStore.TryGetValue(senderId, out var score);
            return Task.FromResult(score);
        }

        public Task UpdateReputationAsync(string senderId, bool isPositiveInteraction)
        {
            _reputationStore.AddOrUpdate(senderId,
                addValue: isPositiveInteraction ? 1.0 : -1.0,
                updateValueFactory: (_, current) =>
                    isPositiveInteraction ? current + 1 : current - 1);

            return Task.CompletedTask;
        }
    }
}
