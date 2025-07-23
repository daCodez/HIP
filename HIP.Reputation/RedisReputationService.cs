using System;
using System.Collections.Generic;
using System.Text;
using StackExchange.Redis;

namespace HIP.Reputation
{
    public class RedisReputationService : IReputationService
    {
        private readonly IDatabase _db;
        private const string Prefix = "reputation:";

        public RedisReputationService(IConnectionMultiplexer redis)
        {
            _db = redis.GetDatabase();
        }

        public async Task<double> GetReputationAsync(string senderId)
        {
            var value = await _db.StringGetAsync(Prefix + senderId);
            return value.HasValue && double.TryParse(value, out var score) ? score : 0;
        }

        public async Task UpdateReputationAsync(string senderId, bool isPositiveInteraction)
        {
            var key = Prefix + senderId;
            double delta = isPositiveInteraction ? 1 : -1;
            await _db.StringIncrementAsync(key, delta);
        }
    }
}
