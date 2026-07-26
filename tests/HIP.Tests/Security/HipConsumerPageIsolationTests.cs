using System.Security.Claims;
using System.Runtime.CompilerServices;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class HipConsumerPageIsolationTests
{
    [Test]
    public async Task Consumer_page_access_uses_the_unique_authenticated_consumer_claim()
    {
        var principal = PrincipalWith(
            new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-current"));
        var serviceCalls = 0;

        var result = await HipConsumerPageAccess.ExecuteAsync(
            principal,
            consumerId =>
            {
                serviceCalls++;
                return Task.FromResult(consumerId);
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo("consumer-current"));
            Assert.That(serviceCalls, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Consumer_page_access_ignores_unauthenticated_claims_and_uses_shared_normalization()
    {
        var principal = new ClaimsPrincipal(
        [
            new ClaimsIdentity(
                [new Claim(HipAuthenticationClaimTypes.ConsumerId, "  consumer-current  ")],
                "authenticated-test"),
            new ClaimsIdentity(
                [new Claim(HipAuthenticationClaimTypes.ConsumerId, "untrusted-consumer")])
        ]);
        var serviceCalls = 0;

        var result = await HipConsumerPageAccess.ExecuteAsync(
            principal,
            consumerId =>
            {
                serviceCalls++;
                return Task.FromResult(consumerId);
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo("consumer-current"));
            Assert.That(serviceCalls, Is.EqualTo(1));
        });
    }

    [TestCase("missing")]
    [TestCase("blank")]
    [TestCase("duplicate")]
    public async Task Invalid_consumer_claims_fail_before_any_service_call(string scenario)
    {
        var principal = scenario switch
        {
            "blank" => PrincipalWith(
                new Claim(HipAuthenticationClaimTypes.ConsumerId, "   ")),
            "duplicate" => PrincipalWith(
                new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-current"),
                new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-current")),
            _ => PrincipalWith()
        };
        var serviceCalls = 0;

        var result = await HipConsumerPageAccess.ExecuteAsync(
            principal,
            consumerId =>
            {
                serviceCalls++;
                return Task.FromResult(consumerId);
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Value, Is.Null);
            Assert.That(serviceCalls, Is.Zero);
        });
    }

    [Test]
    public async Task Settings_reauthorizes_immediately_before_persistence()
    {
        var sequence = new List<string>();
        var authorization = new RecordingAuthorizationService(
            sequence,
            AuthorizationResult.Success());
        var principal = PrincipalWith(
            new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-current"));

        var result = await HipConsumerPageAccess.ExecuteAuthorizedAsync(
            principal,
            authorization,
            ConsumerPolicies.CanUseConsumerPortal,
            consumerId =>
            {
                sequence.Add($"persist:{consumerId}");
                return "saved";
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo("saved"));
            Assert.That(authorization.PolicyName, Is.EqualTo(ConsumerPolicies.CanUseConsumerPortal));
            Assert.That(sequence, Is.EqualTo(new[]
            {
                $"authorize:{ConsumerPolicies.CanUseConsumerPortal}",
                "persist:consumer-current"
            }));
        });
    }

    [Test]
    public async Task Denied_settings_reauthorization_makes_no_persistence_call()
    {
        var sequence = new List<string>();
        var authorization = new RecordingAuthorizationService(
            sequence,
            AuthorizationResult.Failed());
        var principal = PrincipalWith(
            new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-current"));

        var result = await HipConsumerPageAccess.ExecuteAuthorizedAsync(
            principal,
            authorization,
            ConsumerPolicies.CanUseConsumerPortal,
            consumerId =>
            {
                sequence.Add($"persist:{consumerId}");
                return "saved";
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Value, Is.Null);
            Assert.That(sequence, Is.EqualTo(new[]
            {
                $"authorize:{ConsumerPolicies.CanUseConsumerPortal}"
            }));
        });
    }

    [Test]
    public async Task Async_device_mutation_reauthorizes_immediately_before_persistence()
    {
        var sequence = new List<string>();
        var authorization = new RecordingAuthorizationService(
            sequence,
            AuthorizationResult.Success());
        var principal = PrincipalWith(
            new Claim(HipAuthenticationClaimTypes.ConsumerId, "consumer-current"));

        var result = await HipConsumerPageAccess.ExecuteAuthorizedAsync(
            principal,
            authorization,
            ConsumerPolicies.CanUseConsumerPortal,
            async consumerId =>
            {
                await Task.Yield();
                sequence.Add($"persist-async:{consumerId}");
                return "revoked";
            });

        Assert.Multiple(() =>
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo("revoked"));
            Assert.That(sequence, Is.EqualTo(new[]
            {
                $"authorize:{ConsumerPolicies.CanUseConsumerPortal}",
                "persist-async:consumer-current"
            }));
        });
    }

    [Test]
    public void Consumer_pages_use_claim_bound_access_and_devices_do_not_enumerate_global_licenses()
    {
        var root = RepositoryRoot();
        var claimBoundPages = new[]
        {
            "ConsumerScans.razor",
            "ConsumerReports.razor",
            "ConsumerAppeals.razor",
            "ConsumerSettingsPage.razor",
            "ConsumerHome.razor",
            "ConsumerLicenses.razor",
            "ConsumerAccountSecurity.razor",
            "ConsumerCertificates.razor"
        };

        Assert.Multiple(() =>
        {
            foreach (var fileName in claimBoundPages)
            {
                var source = ReadPage(root, fileName);
                Assert.That(source, Does.Not.Contain("\"development-consumer\""), fileName);
                Assert.That(source, Does.Contain("HipConsumerPageAccess.Execute"), fileName);
                Assert.That(source, Does.Contain("AuthenticationStateProvider"), fileName);
            }


            var certificates = ReadPage(root, "ConsumerCertificates.razor");
            Assert.That(certificates, Does.Contain("@page \"/consumer/certificates\""));
            Assert.That(certificates, Does.Contain("IDomainCertificateOwnerQuery"));
            Assert.That(certificates, Does.Contain("IDomainCertificateEnrollmentService"));
            Assert.That(certificates, Does.Contain("HipConsumerPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(certificates, Does.Contain("ConsumerPolicies.CanUseConsumerPortal"));
            Assert.That(certificates, Does.Contain("EnrollmentService.StartAsync"));
            Assert.That(certificates, Does.Contain("Start verification"));
            Assert.That(certificates, Does.Contain("Copy DNS record"));
            Assert.That(certificates, Does.Contain("EnrollmentService.CheckDnsAsync"));
            Assert.That(certificates, Does.Contain("Check DNS"));
            Assert.That(certificates, Does.Contain("EnrollmentService.PrepareWebsiteVerificationAsync"));
            Assert.That(certificates, Does.Contain("Prepare website file"));
            Assert.That(certificates, Does.Contain("Download hip.json"));
            Assert.That(certificates, Does.Contain("EnrollmentService.CheckWebsiteAsync"));
            Assert.That(certificates, Does.Contain("Check website"));
            Assert.That(certificates, Does.Contain("/.well-known/hip.json"));
            Assert.That(certificates, Does.Contain("_hip."));
            Assert.That(certificates, Does.Contain("Domain ownership"));
            Assert.That(certificates, Does.Contain("Certificate status"));
            Assert.That(certificates, Does.Contain("Current HIP score"));
            Assert.That(certificates, Does.Contain("Certificate expiration"));
            Assert.That(certificates, Does.Contain("Domain added"));
            Assert.That(certificates, Does.Contain("DNS verified"));
            Assert.That(certificates, Does.Contain("Website verified"));
            Assert.That(certificates, Does.Contain("Identity completed"));
            Assert.That(certificates, Does.Contain("Security review completed"));
            Assert.That(certificates, Does.Contain("Certificate issued"));
            Assert.That(certificates, Does.Contain("Monitoring active"));
            Assert.That(certificates, Does.Not.Contain("OwnerId"));

            var navigation = File.ReadAllText(Path.Combine(
                root,
                "src",
                "HIP.Web",
                "Components",
                "Layout",
                "ControlCenterNav.razor"));
            Assert.That(navigation, Does.Contain("href=\"consumer/certificates\""));

            var settings = ReadPage(root, "ConsumerSettingsPage.razor");
            var save = Section(settings, "private async Task SaveAsync()", "private void Apply");
            AssertGateBeforeMutation(
                save,
                "HipConsumerPageAccess.ExecuteAuthorizedAsync",
                "ConsumerPortalService.SaveSettingsAsync");
            Assert.That(save, Does.Contain("ConsumerPolicies.CanUseConsumerPortal"));

            var devices = ReadPage(root, "ConsumerDevices.razor") +
                          ReadPage(root, "ConsumerDevices.razor.cs");
            Assert.That(devices, Does.Not.Contain("ISetupCodeLicenseService"));
            Assert.That(devices, Does.Not.Contain("ListLicenses"));
            Assert.That(devices, Does.Contain("IDeviceRegistrationService"));
            Assert.That(devices, Does.Contain("AuthenticationStateProvider"));
            Assert.That(devices, Does.Contain("HipConsumerPageAccess.ExecuteAsync"));
            Assert.That(devices, Does.Contain("hip-device-registration.js"));
            Assert.That(devices, Does.Contain("inspectDeviceRegistrationSupport"));
            Assert.That(devices, Does.Contain("browser profile is blocking local device-key storage"));
            Assert.That(devices, Does.Contain("ReconcileLocalKeysAsync"));

            var register = Section(devices, "private async Task RegisterAsync()", "private async Task RevokeAsync");
            AssertGateBeforeMutation(
                register,
                "HipConsumerPageAccess.ExecuteAuthorizedAsync",
                "DeviceRegistrationService.IssueChallengeAsync");
            Assert.That(register, Does.Contain("DeviceRegistrationService.CompleteAsync"));
            Assert.That(register, Does.Contain("prepareDeviceKey"));
            Assert.That(register, Does.Contain("activateDeviceKey"));

            var revoke = Section(devices, "private async Task RevokeAsync", "private async Task LoadDevicesAsync");
            AssertGateBeforeMutation(
                revoke,
                "HipConsumerPageAccess.ExecuteAuthorizedAsync",
                "DeviceRegistrationService.RevokeAsync");

            var deviceJavaScript = File.ReadAllText(Path.Combine(
                root,
                "src",
                "HIP.Web",
                "wwwroot",
                "js",
                "hip-device-registration.js"));
            Assert.That(deviceJavaScript, Does.Contain("reconcileDeviceKeys"));
            Assert.That(deviceJavaScript, Does.Contain("state: \"pending\""));
            Assert.That(deviceJavaScript, Does.Contain("state: \"active\""));
            Assert.That(deviceJavaScript, Does.Contain("false,").And.Contain("indexedDB"));
            Assert.That(deviceJavaScript, Does.Not.Contain("exportPkcs8").IgnoreCase);
        });
    }

    private static ClaimsPrincipal PrincipalWith(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "test"));

    private static string ReadPage(string root, string fileName) =>
        File.ReadAllText(Path.Combine(
            root,
            "src",
            "HIP.Web",
            "Components",
            "Pages",
            fileName));

    private static void AssertGateBeforeMutation(string source, string gate, string mutation)
    {
        var gateIndex = source.IndexOf(gate, StringComparison.Ordinal);
        var mutationIndex = source.IndexOf(mutation, StringComparison.Ordinal);
        Assert.That(gateIndex, Is.GreaterThanOrEqualTo(0), $"Expected gate '{gate}'.");
        Assert.That(mutationIndex, Is.GreaterThan(gateIndex), $"Expected '{gate}' before '{mutation}'.");
    }

    private static string Section(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0), $"Could not find '{startMarker}'.");
        var end = source.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        Assert.That(end, Is.GreaterThan(start), $"Could not find '{endMarker}' after '{startMarker}'.");
        return source[start..end];
    }

    private static string RepositoryRoot([CallerFilePath] string sourceFilePath = "")
    {
        foreach (var startPath in new[] { Path.GetDirectoryName(sourceFilePath), TestContext.CurrentContext.TestDirectory })
        {
            var directory = new DirectoryInfo(startPath!);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
                {
                    return directory.FullName;
                }

                directory = directory.Parent;
            }
        }

        throw new DirectoryNotFoundException("Could not locate the HIP repository root.");
    }

    private sealed class RecordingAuthorizationService(
        ICollection<string> sequence,
        AuthorizationResult result) : IAuthorizationService
    {
        public string? PolicyName { get; private set; }

        public Task<AuthorizationResult> AuthorizeAsync(
            ClaimsPrincipal user,
            object? resource,
            IEnumerable<IAuthorizationRequirement> requirements) =>
            Task.FromResult(result);

        public Task<AuthorizationResult> AuthorizeAsync(
            ClaimsPrincipal user,
            object? resource,
            string policyName)
        {
            PolicyName = policyName;
            sequence.Add($"authorize:{policyName}");
            return Task.FromResult(result);
        }
    }
}
