using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Rules;
using HIP.Tests.Rules;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class AdminRuleActorBindingTests
{
    /// <summary>
    /// Confirms advanced JSON cannot supply persisted workflow or audit attribution metadata.
    /// </summary>
    [Test]
    public async Task Save_binds_advanced_json_metadata_to_the_authenticated_actor()
    {
        const string authenticatedActor = "hip-user:v1:authenticated-rule-admin";
        var (service, repository, audit, jsonService) = Services();
        var forgedRule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            CreatedBy = "forged-creator",
            ApprovalStatus = ApprovalStatus.Approved,
            Version = 999
        };
        var forgedJson = jsonService.ToJson(forgedRule).TrimEnd();
        forgedJson = forgedJson[..^1] + """
            ,
              "status": "Active",
              "approvedBy": "forged-approver",
              "updatedBy": "forged-updater",
              "createdAtUtc": "2000-01-01T00:00:00Z",
              "approvedAtUtc": "2000-01-01T00:00:00Z",
              "updatedAtUtc": "2000-01-01T00:00:00Z"
            }
            """;
        var parsed = jsonService.TryParse(forgedJson, out var parsedRule, out var errors);

        Assert.That(parsed, Is.True, string.Join(" ", errors));
        var saved = await service.SaveAsync(parsedRule!, authenticatedActor, CancellationToken.None);
        var persisted = await repository.GetByIdAsync(saved.RuleId, CancellationToken.None);
        var persistedJson = jsonService.ToJson(persisted!);
        var auditEntry = (await audit.ListAsync(CancellationToken.None)).Single();

        Assert.Multiple(() =>
        {
            Assert.That(persisted!.CreatedBy, Is.EqualTo(authenticatedActor));
            Assert.That(persisted.ApprovalStatus, Is.EqualTo(ApprovalStatus.Pending));
            Assert.That(persisted.Version, Is.EqualTo(1));
            Assert.That(persistedJson, Does.Not.Contain("approvedBy"));
            Assert.That(persistedJson, Does.Not.Contain("updatedBy"));
            Assert.That(persistedJson, Does.Not.Contain("createdAtUtc"));
            Assert.That(persistedJson, Does.Not.Contain("approvedAtUtc"));
            Assert.That(persistedJson, Does.Not.Contain("updatedAtUtc"));
            Assert.That(auditEntry.ActorId, Is.EqualTo(authenticatedActor));
        });
    }

    /// <summary>
    /// Confirms updates preserve original creation attribution while recording a new actor and version.
    /// </summary>
    [Test]
    public async Task Save_preserves_creator_and_server_controls_update_metadata()
    {
        const string creator = "hip-user:v1:creator";
        const string updater = "hip-user:v1:updater";
        var (service, _, audit, _) = Services();
        var created = await service.SaveAsync(
            RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
            {
                CreatedBy = "forged-creator",
                ApprovalStatus = ApprovalStatus.Approved,
                Version = 888
            },
            creator,
            CancellationToken.None);

        var updated = await service.SaveAsync(
            created with
            {
                Description = "Updated by an authenticated administrator.",
                CreatedBy = "forged-replacement-creator",
                ApprovalStatus = ApprovalStatus.Approved,
                Version = 999
            },
            updater,
            CancellationToken.None);
        var auditEntries = await audit.ListAsync(CancellationToken.None);
        var updateAudit = auditEntries.Single(entry => entry.AfterMetadata["version"] == "2");

        Assert.Multiple(() =>
        {
            Assert.That(updated.CreatedBy, Is.EqualTo(creator));
            Assert.That(updated.ApprovalStatus, Is.EqualTo(ApprovalStatus.Pending));
            Assert.That(updated.Version, Is.EqualTo(2));
            Assert.That(updateAudit.ActorId, Is.EqualTo(updater));
        });
    }

    /// <summary>
    /// Confirms an invalid legacy creator is repaired from the authenticated update actor.
    /// </summary>
    [Test]
    public async Task Save_repairs_a_blank_legacy_creator_from_the_authenticated_actor()
    {
        const string updater = "hip-user:v1:legacy-record-updater";
        var (service, repository, _, _) = Services();
        var legacy = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            CreatedBy = string.Empty,
            Version = 4
        };
        await repository.SaveAsync(legacy, CancellationToken.None);

        var updated = await service.SaveAsync(
            legacy with { Description = "Repairs invalid historical attribution." },
            updater,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(updated.CreatedBy, Is.EqualTo(updater));
            Assert.That(updated.Version, Is.EqualTo(5));
        });
    }

    /// <summary>
    /// Confirms the interactive save path reauthorizes and resolves only server-authenticated identity.
    /// </summary>
    [Test]
    public void Interactive_save_uses_the_authenticated_hip_actor_with_development_only_fallback()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Web",
            "Components",
            "Pages",
            "AdminRules.razor"));
        var savePath = Section(source, "private async Task SaveRule()", "private async Task RunSimulation()");

        Assert.Multiple(() =>
        {
            Assert.That(savePath, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(savePath, Does.Contain("AdminPolicies.CanManageRules"));
            Assert.That(savePath, Does.Contain("HipAuthenticationClaimTypes.ActorId"));
            Assert.That(savePath, Does.Contain("HostEnvironment.IsDevelopment()"));
            Assert.That(savePath, Does.Contain("authenticationState.User.Identity?.Name"));
            Assert.That(savePath, Does.Contain("SaveAsync(rule, actor, CancellationToken.None)"));
            Assert.That(savePath.IndexOf("var actor = await RequireRecentActorAsync();", StringComparison.Ordinal),
                Is.LessThan(savePath.IndexOf("SaveAsync(rule, actor, CancellationToken.None)", StringComparison.Ordinal)));
        });
    }

    private static (AdminRuleService Service, InMemoryRuleRepository Repository, AuditLogService Audit, RuleJsonService JsonService) Services()
    {
        var repository = new InMemoryRuleRepository();
        var audit = new AuditLogService(new InMemoryAuditLogRepository());
        var matching = new RuleMatchingEngine();
        return (
            new AdminRuleService(
                new TrustRuleValidator(),
                repository,
                new RuleSimulationService(new RuleActionApplier(matching)),
                audit),
            repository,
            audit,
            new RuleJsonService(new TrustRuleValidator()));
    }

    private static string Section(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0), $"Could not find '{startMarker}'.");
        var end = source.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        Assert.That(end, Is.GreaterThan(start), $"Could not find '{endMarker}' after '{startMarker}'.");
        return source[start..end];
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
