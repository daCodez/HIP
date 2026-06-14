using System.Text.Json;
using FluentValidation;
using FluentValidation.Results;
using HIP.Application.Review;
using HIP.Application.SiteSafety;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Verifies admin-managed Site Safety rules remain structured, privacy-safe, and rollback-capable.
/// </summary>
[TestFixture]
public sealed class AdminSiteSafetyRuleTests
{
    /// <summary>
    /// Admin rules are created in Draft/Simulation mode so they cannot enforce before review.
    /// </summary>
    [Test]
    public async Task Admin_rule_can_be_created_in_draft_mode()
    {
        var service = CreateService();
        var created = await service.CreateAsync(ValidRule("Executable download with scam wording"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(created.Status, Is.EqualTo(AdminSiteSafetyRuleStatus.Draft));
            Assert.That(created.Mode, Is.EqualTo(AdminSiteSafetyRuleMode.Simulation));
            Assert.That(created.Version, Is.EqualTo(1));
        });
    }

    /// <summary>
    /// Field names are allow-listed so rules cannot reach arbitrary scan internals.
    /// </summary>
    [Test]
    public void Invalid_field_names_are_rejected()
    {
        var rule = ValidRule("Bad field") with
        {
            Conditions = [Condition("RawPageHtml", AdminSiteSafetyRuleOperator.Equals, "x")]
        };

        Assert.ThrowsAsync<ValidationException>(() => ValidateAsync(rule));
    }

    /// <summary>
    /// Operators are constrained to the safe enum values.
    /// </summary>
    [Test]
    public void Invalid_operators_are_rejected()
    {
        var rule = ValidRule("Bad operator") with
        {
            Conditions = [Condition("Domain", (AdminSiteSafetyRuleOperator)999, "example.com")]
        };

        Assert.ThrowsAsync<ValidationException>(() => ValidateAsync(rule));
    }

    /// <summary>
    /// Raw-code markers are rejected because admin rules are data, not executable scripts.
    /// </summary>
    [Test]
    public void Rule_cannot_execute_raw_code()
    {
        var rule = ValidRule("Raw code") with
        {
            Conditions = [Condition("Domain", AdminSiteSafetyRuleOperator.Contains, "eval(alert(1))")]
        };

        Assert.ThrowsAsync<ValidationException>(() => ValidateAsync(rule));
    }

    /// <summary>
    /// Private fields such as page text and passwords are unavailable to admin rules.
    /// </summary>
    [Test]
    public void Rule_cannot_access_private_fields()
    {
        var rule = ValidRule("Private field") with
        {
            Conditions = [Condition("PageText", AdminSiteSafetyRuleOperator.Contains, "secret")]
        };

        Assert.ThrowsAsync<ValidationException>(() => ValidateAsync(rule));
    }

    /// <summary>
    /// Simulation rules can match and be reported without changing final scores.
    /// </summary>
    [Test]
    public async Task Rule_runs_in_simulation_mode_without_affecting_final_score()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ValidRule("Simulation rule") with
        {
            Status = AdminSiteSafetyRuleStatus.Active,
            Mode = AdminSiteSafetyRuleMode.Simulation,
            Effects = new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 90, AddReason: "Simulation-only download risk.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://simulation-rule.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DownloadRiskScore, Is.EqualTo(0));
            Assert.That(result.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.IsSimulationOnly));
        });
    }

    /// <summary>
    /// Watch-only rules are visible to admins but cannot change user-facing risk scores.
    /// </summary>
    [Test]
    public async Task Watch_only_rule_does_not_affect_final_score()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ValidRule("Watch rule") with
        {
            Status = AdminSiteSafetyRuleStatus.Active,
            Mode = AdminSiteSafetyRuleMode.WatchOnly,
            Effects = new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 90, AddReason: "Watch-only download risk.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://watch-rule.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DownloadRiskScore, Is.EqualTo(0));
            Assert.That(result.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.IsSimulationOnly));
        });
    }

    /// <summary>
    /// Enforced approved rules affect the score using structured effects.
    /// </summary>
    [Test]
    public async Task Rule_in_enforced_mode_affects_score()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ApprovedRule("Enforced rule") with
        {
            Effects = new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 75, AddReason: "Executable download pattern matched.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://enforced-rule.example"), CancellationToken.None);

        Assert.That(result.DownloadRiskScore, Is.EqualTo(75));
    }

    /// <summary>
    /// Admin rules can add user-facing reasons and warnings without exposing private content.
    /// </summary>
    [Test]
    public async Task Rule_can_add_reasons_and_warnings()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ApprovedRule("Warning rule") with
        {
            Effects = new AdminSiteSafetyRuleEffects(AddReason: "Admin rule reason.", AddWarning: "Admin rule warning.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://warning-rule.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Reasons, Has.Some.EqualTo("Admin rule reason."));
            Assert.That(result.Warnings, Has.Some.EqualTo("Admin rule warning."));
        });
    }

    /// <summary>
    /// Admin rules can lower confidence without directly deciding trust.
    /// </summary>
    [Test]
    public async Task Rule_can_lower_confidence()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ApprovedRule("Confidence rule") with
        {
            Effects = new AdminSiteSafetyRuleEffects(LowerConfidence: 40, AddReason: "Admin confidence warning.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://confidence-rule.example"), CancellationToken.None);

        Assert.That(result.ConfidenceLevel, Is.EqualTo("Low"));
    }

    /// <summary>
    /// Admin rules can request review through metadata instead of directly changing private data.
    /// </summary>
    [Test]
    public async Task Rule_can_send_result_to_admin_review()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ApprovedRule("Review rule") with
        {
            Effects = new AdminSiteSafetyRuleEffects(SendToAdminReview: true, AddReason: "Admin review requested.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://review-rule.example"), CancellationToken.None);

        Assert.That(result.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.SendToAdminReview));
    }

    /// <summary>
    /// Admin rules can add explicit positive and negative signal text without raw page content.
    /// </summary>
    [Test]
    public async Task Rule_can_add_positive_and_negative_signals()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ApprovedRule("Signal rule") with
        {
            Effects = new AdminSiteSafetyRuleEffects(
                IncreaseDownloadRisk: 20,
                AddPositiveSignal: "Admin found a limited positive trust signal.",
                AddNegativeSignal: "Admin found a download risk signal.",
                AddReason: "Admin signal rule matched.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://signal-rule.example"), CancellationToken.None);

        Assert.That(result.NegativeSignals, Has.Some.EqualTo("Admin found a download risk signal."));
    }

    /// <summary>
    /// Rule simulation explains matched conditions and impacts before enforcement is allowed.
    /// </summary>
    [Test]
    public void Simulation_output_includes_plain_english_impact()
    {
        var service = CreateService();
        var rule = ValidRule("Simulation output") with
        {
            Conditions = [Condition("ExecutableDownloadCount", AdminSiteSafetyRuleOperator.GreaterThan, 0)],
            Severity = SiteSafetyRuleSeverity.High,
            Effects = new AdminSiteSafetyRuleEffects(
                IncreaseDownloadRisk: 45,
                AddReason: "Executable download matched.",
                AddWarning: "Executable download should be reviewed.",
                LowerConfidence: 20,
                SendToAdminReview: true)
        };

        var result = service.Simulate(rule, new AdminSiteSafetyRuleSimulationInput(ExecutableDownloadCount: 1));

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.True);
            Assert.That(result.MatchedCount, Is.EqualTo(1));
            Assert.That(result.RiskImpact, Is.EqualTo(45));
            Assert.That(result.ReasonsAdded, Has.Some.EqualTo("Executable download matched."));
            Assert.That(result.WarningsCreated, Has.Some.EqualTo("Executable download should be reviewed."));
            Assert.That(result.ConfidenceImpact, Is.EqualTo(20));
            Assert.That(result.SendsToAdminReview, Is.True);
            Assert.That(result.ApprovalRequired, Is.True);
            Assert.That(result.RecommendedMode, Is.EqualTo(AdminSiteSafetyRuleMode.WatchOnly));
        });
    }

    /// <summary>
    /// Simulation returns matched and failed conditions separately so admins can see why a rule did or did not fire.
    /// </summary>
    [Test]
    public void Simulation_returns_matched_and_failed_conditions()
    {
        var service = CreateService();
        var rule = ValidRule("Condition diagnostics") with
        {
            Conditions =
            [
                Condition("ExecutableDownloadCount", AdminSiteSafetyRuleOperator.GreaterThan, 0),
                Condition("HasPaymentField", AdminSiteSafetyRuleOperator.Equals, true)
            ],
            Effects = new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 20, AddReason: "Download condition matched.")
        };

        var result = service.Simulate(rule, new AdminSiteSafetyRuleSimulationInput(ExecutableDownloadCount: 1, HasPaymentField: false));

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.False);
            Assert.That(result.ConditionResults.Count, Is.EqualTo(2));
            Assert.That(result.MatchedConditions, Has.Some.Contains("ExecutableDownloadCount"));
            Assert.That(result.FailedConditions, Has.Some.Contains("HasPaymentField"));
            Assert.That(result.RiskScoreImpact, Is.EqualTo(0));
        });
    }

    /// <summary>
    /// Simulation exposes trust, status, warning, reason, and confidence impacts without enforcing them.
    /// </summary>
    [Test]
    public void Simulation_output_includes_trust_status_warning_reason_and_confidence_impacts()
    {
        var service = CreateService();
        var rule = ValidRule("Full diagnostics") with
        {
            Conditions = [Condition("Domain", AdminSiteSafetyRuleOperator.EndsWith, ".example")],
            Effects = new AdminSiteSafetyRuleEffects(
                DecreaseDomainTrust: 15,
                AddReason: "Admin trust review matched.",
                AddWarning: "Admin warning would be shown.",
                SetStatusOverride: SiteSafetyScanStatus.Suspicious,
                LowerConfidence: 25)
        };

        var result = service.Simulate(rule, new AdminSiteSafetyRuleSimulationInput(Url: "https://full-diagnostics.example"));

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.True);
            Assert.That(result.TrustScoreImpact, Is.EqualTo(-15));
            Assert.That(result.StatusImpact, Is.EqualTo(SiteSafetyScanStatus.Suspicious));
            Assert.That(result.ReasonsAdded, Has.Some.EqualTo("Admin trust review matched."));
            Assert.That(result.WarningsAdded, Has.Some.EqualTo("Admin warning would be shown."));
            Assert.That(result.ConfidenceImpact, Is.EqualTo(25));
        });
    }

    /// <summary>
    /// Dangerous overrides can be simulated as a draft, but the output clearly requires approval and watch mode.
    /// </summary>
    [Test]
    public void Dangerous_override_simulation_requires_approval()
    {
        var service = CreateService();
        var rule = ValidRule("Dangerous simulation") with
        {
            Severity = SiteSafetyRuleSeverity.High,
            Effects = new AdminSiteSafetyRuleEffects(
                SetStatusOverride: SiteSafetyScanStatus.Dangerous,
                AddWarning: "Dangerous override would require approval.")
        };

        var result = service.Simulate(rule, new AdminSiteSafetyRuleSimulationInput(Url: "https://dangerous-simulation.example"));

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.True);
            Assert.That(result.StatusImpact, Is.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.ApprovalRequired, Is.True);
            Assert.That(result.RecommendedMode, Is.EqualTo(AdminSiteSafetyRuleMode.WatchOnly));
        });
    }

    /// <summary>
    /// Disabled rule simulation can explain condition diagnostics but must not report active score impact.
    /// </summary>
    [Test]
    public void Disabled_rule_does_not_simulate_as_active()
    {
        var service = CreateService();
        var rule = ValidRule("Disabled simulation") with
        {
            Status = AdminSiteSafetyRuleStatus.Disabled,
            Effects = new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 80, AddReason: "Disabled impact.")
        };

        var result = service.Simulate(rule, new AdminSiteSafetyRuleSimulationInput(Url: "https://disabled-simulation.example"));

        Assert.Multiple(() =>
        {
            Assert.That(result.Matched, Is.False);
            Assert.That(result.ConditionResults.All(condition => condition.Matched), Is.True);
            Assert.That(result.RiskScoreImpact, Is.EqualTo(0));
            Assert.That(result.ReasonsAdded, Is.Empty);
            Assert.That(result.Recommendation, Does.Contain("disabled"));
        });
    }

    /// <summary>
    /// Admin rules cannot mark an otherwise unknown clean site as trusted by themselves.
    /// </summary>
    [Test]
    public void Rule_cannot_mark_unknown_clean_site_trusted()
    {
        var rule = ValidRule("Clean override") with
        {
            Effects = new AdminSiteSafetyRuleEffects(SetStatusOverride: SiteSafetyScanStatus.Clean)
        };

        Assert.ThrowsAsync<ValidationException>(() => ValidateAsync(rule));
    }

    /// <summary>
    /// Dangerous overrides require high severity and explicit approval metadata.
    /// </summary>
    [Test]
    public void Rule_cannot_mark_dangerous_without_approval()
    {
        var rule = ValidRule("Dangerous override") with
        {
            Severity = SiteSafetyRuleSeverity.High,
            Status = AdminSiteSafetyRuleStatus.Active,
            Mode = AdminSiteSafetyRuleMode.Enforced,
            Effects = new AdminSiteSafetyRuleEffects(SetStatusOverride: SiteSafetyScanStatus.Dangerous)
        };

        Assert.ThrowsAsync<ValidationException>(() => ValidateAsync(rule));
    }

    /// <summary>
    /// Updating a rule stores the previous version for audit and rollback.
    /// </summary>
    [Test]
    public async Task Rule_version_is_stored_when_updated()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        var service = CreateService(repository);
        var original = await service.CreateAsync(ValidRule("Versioned rule"), CancellationToken.None);
        var updated = await service.UpdateAsync(original with { Description = "Changed description." }, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(updated.Version, Is.EqualTo(2));
            Assert.That(updated.PreviousVersionId, Is.EqualTo("versioned-rule:v1"));
            Assert.That(updated.IsRollbackAvailable, Is.True);
            Assert.That(repository.GetPreviousVersionAsync(original.RuleId, CancellationToken.None).Result, Is.Not.Null);
        });
    }

    /// <summary>
    /// Rollback restores the previous rule version.
    /// </summary>
    [Test]
    public async Task Rule_rollback_restores_previous_version()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        var service = CreateService(repository);
        var original = await service.CreateAsync(ValidRule("Rollback rule"), CancellationToken.None);
        await service.UpdateAsync(original with { Description = "Changed description." }, CancellationToken.None);

        var restored = await service.RollbackAsync(original.RuleId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(restored.Description, Is.EqualTo(original.Description));
            Assert.That(restored.Version, Is.EqualTo(3));
            Assert.That(restored.PreviousVersionId, Is.EqualTo("rollback-rule:v2"));
        });
    }

    /// <summary>
    /// Rollback writes a new audit entry without erasing earlier rule-change audit entries.
    /// </summary>
    [Test]
    public async Task Rollback_does_not_erase_audit_history()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        var audit = new AuditLogService(new InMemoryAuditLogRepository());
        var service = CreateService(repository, audit);
        var original = await service.CreateAsync(ValidRule("Audited rollback"), CancellationToken.None);
        await service.UpdateAsync(original with { Description = "Changed description.", UpdatedBy = "admin-a" }, CancellationToken.None);
        var auditCountBeforeRollback = audit.List().Count;

        await service.RollbackAsync(original.RuleId, "admin-b", CancellationToken.None);
        var entries = audit.List();

        Assert.Multiple(() =>
        {
            Assert.That(entries.Count, Is.GreaterThan(auditCountBeforeRollback));
            Assert.That(entries.Any(entry => entry.Action == "Admin Site Safety rule updated"), Is.True);
            Assert.That(entries.Any(entry => entry.Action == "Admin Site Safety rule rollback"), Is.True);
        });
    }

    /// <summary>
    /// Approved rules can be activated, disabled, and versioned through the service lifecycle methods.
    /// </summary>
    [Test]
    public async Task Rule_lifecycle_actions_update_status_and_versions()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        var service = CreateService(repository);
        var original = await service.CreateAsync(ValidRule("Lifecycle rule"), CancellationToken.None);
        var approved = await service.ApproveAsync(original.RuleId, "owner", CancellationToken.None);
        var active = await service.ActivateAsync(original.RuleId, "owner", CancellationToken.None);
        var disabled = await service.DisableAsync(original.RuleId, "owner", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(approved.Status, Is.EqualTo(AdminSiteSafetyRuleStatus.Approved));
            Assert.That(active.Status, Is.EqualTo(AdminSiteSafetyRuleStatus.Active));
            Assert.That(active.Mode, Is.EqualTo(AdminSiteSafetyRuleMode.Enforced));
            Assert.That(disabled.Status, Is.EqualTo(AdminSiteSafetyRuleStatus.Disabled));
            Assert.That(disabled.IsRollbackAvailable, Is.True);
        });
    }

    /// <summary>
    /// Disabled rules do not run even if their conditions match.
    /// </summary>
    [Test]
    public async Task Disabled_rule_does_not_run()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ApprovedRule("Disabled rule") with
        {
            Status = AdminSiteSafetyRuleStatus.Disabled,
            Effects = new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 90, AddReason: "Disabled rule matched.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://disabled-rule.example"), CancellationToken.None);

        Assert.That(result.MatchedRules ?? [], Has.None.Matches<SiteSafetyRuleResult>(rule => rule.RuleId == "disabled-rule"));
    }

    /// <summary>
    /// Archived rules are historical records and must not run even if their conditions match.
    /// </summary>
    [Test]
    public async Task Archived_rule_does_not_run()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(ApprovedRule("Archived rule") with
        {
            Status = AdminSiteSafetyRuleStatus.Archived,
            Effects = new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 90, AddReason: "Archived rule matched.")
        }, CancellationToken.None);

        var result = await CreateScanner(repository).ScanAsync(new SiteSafetyScanRequest("https://archived-rule.example"), CancellationToken.None);

        Assert.That(result.MatchedRules ?? [], Has.None.Matches<SiteSafetyRuleResult>(rule => rule.RuleId == "archived-rule"));
    }

    /// <summary>
    /// Rollback cannot restore a historical dangerous enforced rule that lacks approval metadata.
    /// </summary>
    [Test]
    public async Task Dangerous_override_still_requires_approval_after_rollback()
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        var service = CreateService(repository);
        var current = await service.CreateAsync(ValidRule("Unsafe rollback"), CancellationToken.None);
        await repository.SaveVersionAsync(current with
        {
            Status = AdminSiteSafetyRuleStatus.Active,
            Mode = AdminSiteSafetyRuleMode.Enforced,
            Severity = SiteSafetyRuleSeverity.High,
            Effects = new AdminSiteSafetyRuleEffects(SetStatusOverride: SiteSafetyScanStatus.Dangerous),
            ApprovedBy = null,
            ApprovedAtUtc = null
        }, CancellationToken.None);

        Assert.ThrowsAsync<ValidationException>(() => service.RollbackAsync(current.RuleId, "owner", CancellationToken.None));
    }

    /// <summary>
    /// Rollback rejects unknown or unversioned rule targets instead of creating a new rule by mistake.
    /// </summary>
    [Test]
    public void Invalid_rollback_target_is_rejected()
    {
        var service = CreateService();

        Assert.ThrowsAsync<InvalidOperationException>(() => service.RollbackAsync("missing-rule", "owner", CancellationToken.None));
    }

    /// <summary>
    /// Creates a baseline valid admin rule.
    /// </summary>
    private static AdminSiteSafetyRule ValidRule(string name) =>
        new(
            RuleId: Slug(name),
            Name: name,
            Description: "Test rule.",
            TargetType: AdminSiteSafetyRuleTargetType.PageContent,
            Conditions: [Condition("Domain", AdminSiteSafetyRuleOperator.EndsWith, ".example")],
            Effects: new AdminSiteSafetyRuleEffects(AddReason: "Admin rule matched."),
            Severity: SiteSafetyRuleSeverity.Medium,
            EvidenceQuality: SiteSafetyEvidenceQuality.Medium,
            Status: AdminSiteSafetyRuleStatus.Draft,
            Mode: AdminSiteSafetyRuleMode.Simulation,
            CreatedBy: "test-admin",
            CreatedAtUtc: DateTimeOffset.UtcNow,
            ApprovedBy: null,
            ApprovedAtUtc: null,
            Version: 1,
            PreviousVersionId: null,
            IsRollbackAvailable: false);

    /// <summary>
    /// Creates a validated active rule shape for scanner enforcement tests.
    /// </summary>
    private static AdminSiteSafetyRule ApprovedRule(string name) =>
        ValidRule(name) with
        {
            Status = AdminSiteSafetyRuleStatus.Active,
            Mode = AdminSiteSafetyRuleMode.Enforced,
            ApprovedBy = "owner",
            ApprovedAtUtc = DateTimeOffset.UtcNow
        };

    /// <summary>
    /// Creates an admin rule condition from a serializable value.
    /// </summary>
    private static AdminSiteSafetyRuleCondition Condition(string field, AdminSiteSafetyRuleOperator op, object value) =>
        new(field, op, JsonSerializer.SerializeToElement(value));

    /// <summary>
    /// Validates a rule using the production validator.
    /// </summary>
    private static Task ValidateAsync(AdminSiteSafetyRule rule) =>
        new AdminSiteSafetyRuleValidator().ValidateAndThrowAsync(rule, CancellationToken.None);

    /// <summary>
    /// Creates the admin rule service with an optional repository.
    /// </summary>
    private static AdminSiteSafetyRuleService CreateService(IAdminSiteSafetyRuleRepository? repository = null, AuditLogService? auditLogService = null) =>
        new(repository ?? new InMemoryAdminSiteSafetyRuleRepository(), new AdminSiteSafetyRuleValidator(), auditLogService ?? new AuditLogService(new InMemoryAuditLogRepository()));

    /// <summary>
    /// Creates a scanner with a test admin repository and no external providers.
    /// </summary>
    private static SiteSafetyScanner CreateScanner(IAdminSiteSafetyRuleRepository repository) =>
        new(new SiteSafetyScanValidator(), NullLogger<SiteSafetyScanner>.Instance, [], new SiteSafetyRuleOptions { ScanCacheDuration = TimeSpan.Zero }, repository);

    /// <summary>
    /// Creates a stable test rule ID.
    /// </summary>
    private static string Slug(string value) =>
        value.ToLowerInvariant().Replace(' ', '-');
}
