using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemoryReplayProtectionService(HipDbContext db) : IReplayProtectionService
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(15);

    public async Task<bool> TryConsumeAsync(string messageId, string identityId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(messageId) || string.IsNullOrWhiteSpace(identityId))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        var allNonces = await db.ReplayNonces.ToListAsync(cancellationToken);
        var expired = allNonces.Where(x => x.ExpiresAtUtc <= now).ToList();
        if (expired.Count > 0)
        {
            db.ReplayNonces.RemoveRange(expired);
            await db.SaveChangesAsync(cancellationToken);
        }

        var exists = await db.ReplayNonces.AnyAsync(x => x.MessageId == messageId, cancellationToken);
        if (exists)
        {
            return false;
        }

        db.ReplayNonces.Add(new ReplayNonceRecord
        {
            MessageId = messageId,
            IdentityId = identityId,
            CreatedAtUtc = now,
            ExpiresAtUtc = now.Add(Ttl)
        });

        await db.SaveChangesAsync(cancellationToken);
        return true;
    }
}
