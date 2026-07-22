using System.Text;
using HIP.Application.ServiceClients;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Domain.ServiceClients;

namespace HIP.Tests.ServiceClients;

[TestFixture]
public sealed class ServiceClientRegistrationRequestValidatorTests
{
    [TestCase(ServiceClientScopeValues.DomainVerificationCheck, ServiceClientScope.DomainVerificationCheck)]
    [TestCase(ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck, ServiceClientScope.SiteSafetyExternalEvidenceCheck)]
    public void Each_explicit_scope_is_accepted_exactly(
        string scopeValue,
        ServiceClientScope expectedScope)
    {
        var validated = ServiceClientRegistrationRequestValidator.Validate(
            Request(scopes: [scopeValue]));

        Assert.That(validated.Scope, Is.EqualTo(expectedScope));
    }

    [TestCase("domain-verification:write")]
    [TestCase("DOMAIN-VERIFICATION:CHECK")]
    [TestCase("*")]
    [TestCase("domain-verification:*")]
    public void Unknown_case_variant_and_wildcard_scopes_are_rejected(string scope)
    {
        Assert.That(
            () => ServiceClientRegistrationRequestValidator.Validate(Request(scopes: [scope])),
            Throws.ArgumentException);
    }

    [Test]
    public void Duplicate_scope_is_rejected_instead_of_being_collapsed()
    {
        Assert.That(
            () => ServiceClientRegistrationRequestValidator.Validate(
                Request(scopes:
                [
                    ServiceClientScopeValues.DomainVerificationCheck,
                    ServiceClientScopeValues.DomainVerificationCheck
                ])),
            Throws.ArgumentException);
    }

    [Test]
    public void Multiple_distinct_scopes_are_rejected()
    {
        Assert.That(
            () => ServiceClientRegistrationRequestValidator.Validate(
                Request(scopes:
                [
                    ServiceClientScopeValues.DomainVerificationCheck,
                    ServiceClientScopeValues.SiteSafetyExternalEvidenceCheck
                ])),
            Throws.ArgumentException);
    }

    [Test]
    public void Missing_scope_is_rejected()
    {
        Assert.That(
            () => ServiceClientRegistrationRequestValidator.Validate(Request(scopes: Array.Empty<string>())),
            Throws.ArgumentException);
    }

    [Test]
    public void Domain_grants_are_normalized_sorted_and_remain_exact()
    {
        var validated = ServiceClientRegistrationRequestValidator.Validate(
            Request(domains: [" Api.Example.COM. ", "example.com"]));

        Assert.That(validated.DomainGrants, Is.EqualTo(new[] { "api.example.com", "example.com" }));
    }

    [TestCaseSource(nameof(InvalidDomainGrantSets))]
    public void Empty_unbounded_duplicate_and_non_public_domain_grants_are_rejected(
        IReadOnlyCollection<string> domains)
    {
        Assert.That(
            () => ServiceClientRegistrationRequestValidator.Validate(Request(domains: domains)),
            Throws.InstanceOf<ArgumentException>());
    }

    [Test]
    public void Display_name_is_trimmed_and_bounded_by_UTF8_bytes()
    {
        var validated = ServiceClientRegistrationRequestValidator.Validate(
            Request(displayName: "  Evidence checker  "));
        var oversized = new string('\u00e9',
            (ServiceClientRegistrationLimits.MaximumDisplayNameUtf8Bytes / Encoding.UTF8.GetByteCount("\u00e9")) + 1);

        Assert.Multiple(() =>
        {
            Assert.That(validated.DisplayName, Is.EqualTo("Evidence checker"));
            Assert.That(
                () => ServiceClientRegistrationRequestValidator.Validate(Request(displayName: oversized)),
                Throws.InstanceOf<ArgumentOutOfRangeException>());
        });
    }

    [TestCase(null, 90)]
    [TestCase(1, 1)]
    [TestCase(365, 365)]
    public void Lifetime_defaults_to_90_days_and_accepts_the_inclusive_policy_bounds(
        int? requestedLifetimeDays,
        int expectedLifetimeDays)
    {
        var validated = ServiceClientRegistrationRequestValidator.Validate(
            Request(lifetimeDays: requestedLifetimeDays));

        Assert.That(validated.LifetimeDays, Is.EqualTo(expectedLifetimeDays));
    }

    [TestCase(0)]
    [TestCase(366)]
    public void Lifetime_outside_the_one_to_365_day_policy_is_rejected(int lifetimeDays)
    {
        Assert.That(
            () => ServiceClientRegistrationRequestValidator.Validate(Request(lifetimeDays: lifetimeDays)),
            Throws.InstanceOf<ArgumentOutOfRangeException>());
    }

    [Test]
    public void In_memory_secret_wrapper_is_explicitly_redacted_from_string_formatting()
    {
        var secret = new ServiceClientSecret("hip_secret_value_that_is_returned_once");

        Assert.Multiple(() =>
        {
            Assert.That(secret.Reveal(), Is.EqualTo("hip_secret_value_that_is_returned_once"));
            Assert.That(secret.ToString(), Is.EqualTo("[REDACTED]"));
        });
    }

    [Test]
    public void Transition_batch_rejects_a_verifier_embedded_inside_audit_text()
    {
        const string credentialVerifier =
            "pbkdf2-sha256-v1$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        var createdAtUtc = new DateTimeOffset(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);
        var registration = ServiceClientRegistration.Create(
            "hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ",
            "service-client-owner-hmac-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Evidence checker",
            ServiceClientScope.DomainVerificationCheck,
            ["example.com"],
            credentialVerifier,
            createdAtUtc,
            createdAtUtc.AddDays(90));
        var audit = new AuditLogEntry(
            "audit-service-client-1",
            "operator-1",
            "ServiceClientRegistered",
            TargetType.ServiceClient,
            registration.ClientId,
            $"A verifier leak would look like prefix-{credentialVerifier}-suffix.",
            createdAtUtc,
            new Dictionary<string, string>(),
            AuditSeverity.High);

        Assert.That(
            () => new ServiceClientTransitionBatch(registration, expectedAggregateVersion: 0, [audit]),
            Throws.ArgumentException);
    }

    [Test]
    public void Transition_batch_requires_an_exact_service_client_audit_target()
    {
        const string credentialVerifier =
            "pbkdf2-sha256-v1$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        var createdAtUtc = new DateTimeOffset(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);
        var registration = ServiceClientRegistration.Create(
            "hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ",
            "service-client-owner-hmac-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Evidence checker",
            ServiceClientScope.DomainVerificationCheck,
            ["example.com"],
            credentialVerifier,
            createdAtUtc,
            createdAtUtc.AddDays(90));
        var wrongTarget = new AuditLogEntry(
            "audit-service-client-2",
            "operator-1",
            "ServiceClientRegistered",
            TargetType.Organization,
            registration.ClientId,
            "Registered a service client.",
            createdAtUtc,
            new Dictionary<string, string>(),
            AuditSeverity.High);

        Assert.That(
            () => new ServiceClientTransitionBatch(registration, expectedAggregateVersion: 0, [wrongTarget]),
            Throws.ArgumentException);
    }

    [Test]
    public void Transition_batch_requires_exact_target_id_and_UTC_audit_time()
    {
        const string credentialVerifier =
            "pbkdf2-sha256-v1$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        var createdAtUtc = new DateTimeOffset(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);
        var registration = ServiceClientRegistration.Create(
            "hipc_v1_ABCDEFGHIJKLMNOPQRSTUQ",
            "service-client-owner-hmac-sha256-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Evidence checker",
            ServiceClientScope.DomainVerificationCheck,
            ["example.com"],
            credentialVerifier,
            createdAtUtc,
            createdAtUtc.AddDays(90));
        var wrongTargetId = new AuditLogEntry(
            "audit-service-client-3",
            "operator-1",
            "ServiceClientRegistered",
            TargetType.ServiceClient,
            "hipc_v1_BCDEFGHIJKLMNOPQRSTUVA",
            "Registered a service client.",
            createdAtUtc,
            new Dictionary<string, string>(),
            AuditSeverity.High);
        var nonUtcTime = wrongTargetId with
        {
            AuditLogId = "audit-service-client-4",
            TargetId = registration.ClientId,
            CreatedAtUtc = createdAtUtc.ToOffset(TimeSpan.FromHours(1))
        };

        Assert.Multiple(() =>
        {
            Assert.That(
                () => new ServiceClientTransitionBatch(registration, expectedAggregateVersion: 0, [wrongTargetId]),
                Throws.ArgumentException);
            Assert.That(
                () => new ServiceClientTransitionBatch(registration, expectedAggregateVersion: 0, [nonUtcTime]),
                Throws.ArgumentException);
        });
    }

    [Test]
    public void Repository_owner_listing_contract_is_cursor_paged_and_bounded()
    {
        var method = typeof(IServiceClientRepository).GetMethod(
            nameof(IServiceClientRepository.ListByOwnerAsync),
            [
                typeof(string),
                typeof(string),
                typeof(int),
                typeof(CancellationToken)
            ]);
        var parameters = method!.GetParameters();

        Assert.Multiple(() =>
        {
            Assert.That(parameters.Select(parameter => parameter.Name),
                Is.EqualTo(new[] { "ownerScopeId", "cursor", "pageSize", "cancellationToken" }));
            Assert.That(method.ReturnType, Is.EqualTo(typeof(Task<ServiceClientRepositoryPage>)));
            Assert.That(ServiceClientRepositoryPage.MaximumPageSize, Is.EqualTo(100));
        });
    }

    [Test]
    public void Secret_protector_contract_binds_protection_and_verification_to_the_client_identifier()
    {
        var protectParameters = typeof(IServiceClientSecretProtector)
            .GetMethod(nameof(IServiceClientSecretProtector.Protect))!
            .GetParameters();
        var verifyParameters = typeof(IServiceClientSecretProtector)
            .GetMethod(nameof(IServiceClientSecretProtector.Verify))!
            .GetParameters();

        Assert.Multiple(() =>
        {
            Assert.That(protectParameters.Select(parameter => parameter.Name),
                Is.EqualTo(new[] { "clientId", "secret" }));
            Assert.That(verifyParameters.Select(parameter => parameter.Name),
                Is.EqualTo(new[] { "clientId", "presentedSecret", "credentialVerifier" }));
        });
    }

    private static CreateServiceClientRequest Request(
        string displayName = "Evidence checker",
        IReadOnlyCollection<string>? scopes = null,
        IReadOnlyCollection<string>? domains = null,
        int? lifetimeDays = null) =>
        new(
            displayName,
            scopes ?? [ServiceClientScopeValues.DomainVerificationCheck],
            domains ?? ["example.com"],
            lifetimeDays);

    private static IEnumerable<IReadOnlyCollection<string>> InvalidDomainGrantSets()
    {
        yield return Array.Empty<string>();
        yield return Enumerable.Range(0, ServiceClientRegistrationLimits.MaximumDomainGrants + 1)
            .Select(index => $"domain-{index}.example.com")
            .ToArray();
        yield return new[] { "Example.com", "example.com." };
        yield return new[] { "localhost" };
        yield return new[] { "*.example.com" };
    }
}
