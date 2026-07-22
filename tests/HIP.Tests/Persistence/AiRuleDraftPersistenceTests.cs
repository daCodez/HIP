using HIP.Application.Ai;
using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Verifies HIP-0406 create-only encrypted draft persistence.</summary>
public sealed class AiRuleDraftPersistenceTests
{
    [Test]
    public async Task Draft_is_encrypted_create_only_and_retains_simulation_binding()
    {
        var draft = await Draft();
        await using var context = new HipDbContext(
            new DbContextOptionsBuilder<HipDbContext>()
                .UseInMemoryDatabase($"ai-rule-draft-{Guid.NewGuid():N}")
                .Options);
        var repository = new EfAiRuleDraftRepository(Store(context));

        var created = await repository.TryCreateAsync(draft, CancellationToken.None);
        var duplicate = await repository.TryCreateAsync(draft, CancellationToken.None);
        var restored = await repository.GetAsync(draft.DraftId, CancellationToken.None);
        var row = await context.Records.AsNoTracking()
            .SingleAsync(record => record.Partition == "ai-rule-draft");

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.True);
            Assert.That(duplicate, Is.False);
            Assert.That(restored!.SimulationId, Is.EqualTo(draft.SimulationId));
            Assert.That(restored.ProposedRule.Enabled, Is.False);
            Assert.That(row.AggregateVersion, Is.EqualTo(1));
            Assert.That(new DevelopmentHipRecordEncryptor().IsProtectedPayload(row.Json), Is.True);
            Assert.That(row.Json, Does.Not.Contain("urgency-language"));
        });
    }

    private static async Task<AiRuleDraft> Draft()
    {
        var simulations = new InMemoryRuleSimulationResultRepository();
        var approvals = new RuleApprovalWorkflowService(
            new InMemoryRuleApprovalWorkflowRepository(new InMemoryOutboxEventRepository()),
            simulations);
        var service = new AiRuleDraftService(
            new DevelopmentHipAiRiskAnalyzer(),
            new TrustRuleValidator(),
            new RuleSimulationService(new RuleActionApplier(new RuleMatchingEngine())),
            simulations,
            new InMemoryAiRuleDraftRepository(),
            approvals);
        return await service.CreateAsync(
            new HipAiRuleSuggestionRequest(
                "example.com",
                null,
                "Web",
                new HipAiRiskAnalysisResult(
                    RiskStatus.Caution,
                    55,
                    ["One bounded urgency-language signal requires review."],
                    ["UrgencyLanguage"],
                    "ShowCaution",
                    true,
                    true,
                    true,
                    DevelopmentHipAiRiskAnalyzer.ProviderName)),
            CancellationToken.None);
    }

    private static HipRecordStore Store(HipDbContext context) =>
        new(context, new DevelopmentHipRecordEncryptor());
}
