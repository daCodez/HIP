using System.Text.Json.Serialization;
using HIP.Application.Devices;
using HIP.Domain.Devices;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;

namespace HIP.Web.Components.Pages;

public partial class ConsumerDevices : IAsyncDisposable
{
    private const string DeviceModulePath = "./js/hip-device-registration.js";
    private const string BrowserClientVersion = "hip-web-portal/1";

    [Inject] private IDeviceRegistrationService DeviceRegistrationService { get; set; } = default!;
    [Inject] private AuthenticationStateProvider AuthenticationStateProvider { get; set; } = default!;
    [Inject] private IAuthorizationService AuthorizationService { get; set; } = default!;
    [Inject] private IJSRuntime JSRuntime { get; set; } = default!;

    private IReadOnlyList<DeviceRegistrationDeviceResponse> _devices = [];
    private IJSObjectReference? _deviceModule;
    private string _friendlyName = "This browser";
    private string? _accessError;
    private string? _statusMessage;
    private string? _confirmingDeviceId;
    private bool _statusIsError;
    private bool _isLoading = true;
    private bool _isBusy;
    private bool _isRegistering;
    private bool _canUseJavaScript;
    private bool _browserSupportChecked;
    private bool _browserRegistrationSupported;
    private BrowserDeviceSupport? _browserSupport;
    private string _registrationStage = "starting secure registration";

    private int ActiveDeviceCount => _devices.Count(device => device.RevocationState == DeviceRevocationState.Active);
    private int RevokedDeviceCount => _devices.Count - ActiveDeviceCount;
    private bool AtDeviceLimit => ActiveDeviceCount >= DeviceRegistrationPolicy.Default.MaximumDevices;
    private bool RegistrationDisabled => _isBusy || AtDeviceLimit || string.IsNullOrWhiteSpace(_friendlyName) ||
                                         !_browserSupportChecked || !_browserRegistrationSupported;
    private string BrowserReadinessLabel => !_browserSupportChecked
        ? "Checking browser key storage"
        : _browserRegistrationSupported ? "Private key stays in this browser" : "Secure key storage unavailable";
    private string BrowserReadinessShortLabel => !_browserSupportChecked ? "Checking" : _browserRegistrationSupported ? "Ready" : "Unavailable";
    private string BrowserReadinessDescription => !_browserSupportChecked
        ? "HIP is checking whether this browser can create and retain a non-exportable key."
        : _browserRegistrationSupported
            ? "WebCrypto and browser-profile key storage are ready. Proof confirms key possession, not device safety."
            : BrowserSupportFailure(_browserSupport);

    protected override Task OnInitializedAsync() => LoadDevicesAsync();

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (!firstRender)
        {
            return;
        }

        _canUseJavaScript = true;
        await InspectBrowserSupportAsync();
        _ = await ReconcileLocalKeysAsync();
        StateHasChanged();
    }

    private async Task RegisterAsync()
    {
        if (RegistrationDisabled)
        {
            return;
        }

        _isBusy = true;
        _isRegistering = true;
        _statusMessage = null;
        _statusIsError = false;
        PreparedDeviceKey? prepared = null;
        string? stagedDeviceId = null;
        var registrationCompleted = false;

        try
        {
            SetRegistrationProgress("creating a non-exportable browser key");
            var module = await GetDeviceModuleAsync();
            prepared = await module.InvokeAsync<PreparedDeviceKey>("prepareDeviceKey");
            SetRegistrationProgress("requesting a short-lived HIP challenge");
            var authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
            var issuedAccess = await HipConsumerPageAccess.ExecuteAuthorizedAsync(
                authenticationState.User,
                AuthorizationService,
                ConsumerPolicies.CanUseConsumerPortal,
                consumerId => DeviceRegistrationService.IssueChallengeAsync(
                    consumerId,
                    new StartDeviceRegistrationRequest(
                        _friendlyName,
                        DevicePlatformType.BrowserExtension,
                        BrowserClientVersion,
                        Es256DeviceProofVerifier.Algorithm,
                        prepared.PublicKey),
                    CancellationToken.None));
            if (!issuedAccess.Succeeded || issuedAccess.Value is null)
            {
                _accessError = HipConsumerPageAccess.AccessUnavailableMessage;
                return;
            }

            var issued = issuedAccess.Value;
            if (issued.Outcome != DeviceRegistrationOutcome.Succeeded || issued.Challenge is null)
            {
                SetError(issued.Message);
                return;
            }

            var challenge = issued.Challenge;
            SetRegistrationProgress("storing the private key in this browser profile");
            await module.InvokeVoidAsync("stageDeviceKey", prepared.Handle, challenge.DeviceId);
            prepared = null;
            stagedDeviceId = challenge.DeviceId;
            SetRegistrationProgress("proving private-key possession");
            var signature = await module.InvokeAsync<string>(
                "signDeviceChallenge",
                challenge.DeviceId,
                challenge.SigningInput);

            SetRegistrationProgress("saving the verified registration");
            authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
            var completedAccess = await HipConsumerPageAccess.ExecuteAuthorizedAsync(
                authenticationState.User,
                AuthorizationService,
                ConsumerPolicies.CanUseConsumerPortal,
                consumerId => DeviceRegistrationService.CompleteAsync(
                    consumerId,
                    challenge.ChallengeId,
                    new CompleteDeviceRegistrationRequest(challenge.SigningInput, signature),
                    CancellationToken.None));
            if (!completedAccess.Succeeded || completedAccess.Value is null)
            {
                _accessError = HipConsumerPageAccess.AccessUnavailableMessage;
                return;
            }

            var completed = completedAccess.Value;
            if (completed.Outcome != DeviceRegistrationOutcome.Succeeded || completed.Device is null)
            {
                SetError(completed.Message);
                return;
            }

            registrationCompleted = true;
            SetRegistrationProgress("activating this browser's local key");
            await module.InvokeVoidAsync("activateDeviceKey", challenge.DeviceId);
            stagedDeviceId = null;
            _friendlyName = "This browser";
            SetSuccess("This browser is registered. Its private key remains non-exportable in this browser profile.");
            await LoadDevicesAsync();
        }
        catch (JSException exception)
        {
            SetError(registrationCompleted
                ? "The device was registered, but this browser could not activate its local key. Revoke it before trying again."
                : BrowserRegistrationError(exception.Message, _registrationStage));
            if (registrationCompleted)
            {
                await LoadDevicesAsync();
            }
        }
        catch (Exception)
        {
            SetError(registrationCompleted
                ? "The device was registered, but this browser could not finish local key storage. Revoke it before trying again."
                : "This browser could not complete secure device registration. No private key was sent to HIP.");
            if (registrationCompleted)
            {
                await LoadDevicesAsync();
            }
        }
        finally
        {
            if (prepared is not null)
            {
                await DiscardPendingKeyAsync(prepared.Handle);
            }

            if (stagedDeviceId is not null && !registrationCompleted)
            {
                await RemoveLocalKeyAsync(stagedDeviceId);
            }

            _isRegistering = false;
            _isBusy = false;
        }
    }

    private async Task RevokeAsync(DeviceRegistrationDeviceResponse device)
    {
        _isBusy = true;
        _statusMessage = null;
        _statusIsError = false;
        try
        {
            var authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
            var access = await HipConsumerPageAccess.ExecuteAuthorizedAsync(
                authenticationState.User,
                AuthorizationService,
                ConsumerPolicies.CanUseConsumerPortal,
                consumerId => DeviceRegistrationService.RevokeAsync(
                    consumerId,
                    device.DeviceId,
                    CancellationToken.None));
            if (!access.Succeeded || access.Value is null)
            {
                _accessError = HipConsumerPageAccess.AccessUnavailableMessage;
                return;
            }

            var result = access.Value;
            if (result.Outcome != DeviceRegistrationOutcome.Succeeded)
            {
                SetError(result.Message);
                return;
            }

            var localKeyRemoved = await RemoveLocalKeyAsync(device.DeviceId);
            SetSuccess(localKeyRemoved
                ? $"{device.FriendlyName} was revoked and its local key was removed from this browser."
                : $"{device.FriendlyName} was revoked. Its key can no longer authenticate, but local browser storage could not be cleared.");
            await LoadDevicesAsync();
        }
        catch (Exception)
        {
            SetError("HIP could not revoke this device right now. Its existing state has not been changed by this page.");
        }
        finally
        {
            _confirmingDeviceId = null;
            _isBusy = false;
        }
    }

    private async Task LoadDevicesAsync()
    {
        _isLoading = true;
        try
        {
            var authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
            var access = await HipConsumerPageAccess.ExecuteAsync(
                authenticationState.User,
                consumerId => DeviceRegistrationService.ListAsync(consumerId, CancellationToken.None));
            if (!access.Succeeded || access.Value is null)
            {
                _accessError = HipConsumerPageAccess.AccessUnavailableMessage;
                _devices = [];
                return;
            }

            _accessError = null;
            _devices = access.Value.ToArray();
            if (_canUseJavaScript)
            {
                _ = await ReconcileLocalKeysAsync();
            }
        }
        catch (Exception)
        {
            _accessError = "HIP device information is temporarily unavailable. Retry in a moment.";
            _devices = [];
        }
        finally
        {
            _isLoading = false;
        }
    }

    private void BeginRevoke(string deviceId) => _confirmingDeviceId = deviceId;
    private void CancelRevoke() => _confirmingDeviceId = null;
    private void SetError(string message) { _statusMessage = message; _statusIsError = true; }
    private void SetSuccess(string message) { _statusMessage = message; _statusIsError = false; }
    private void SetRegistrationProgress(string stage)
    {
        _registrationStage = stage;
        _statusMessage = $"HIP is {stage}…";
        _statusIsError = false;
        StateHasChanged();
    }

    private async Task<IJSObjectReference> GetDeviceModuleAsync() =>
        _deviceModule ??= await JSRuntime.InvokeAsync<IJSObjectReference>("import", DeviceModulePath);

    private async Task InspectBrowserSupportAsync()
    {
        try
        {
            _browserSupport = await (await GetDeviceModuleAsync())
                .InvokeAsync<BrowserDeviceSupport>("inspectDeviceRegistrationSupport");
            _browserRegistrationSupported = _browserSupport.Supported;
        }
        catch (Exception exception) when (exception is JSException or JSDisconnectedException or InvalidOperationException)
        {
            _browserSupport = null;
            _browserRegistrationSupported = false;
        }
        finally
        {
            _browserSupportChecked = true;
        }
    }

    private async Task DiscardPendingKeyAsync(string handle)
    {
        try { await (await GetDeviceModuleAsync()).InvokeVoidAsync("discardPendingDeviceKey", handle); }
        catch (Exception exception) when (exception is JSException or JSDisconnectedException or InvalidOperationException) { }
    }

    private async Task<bool> RemoveLocalKeyAsync(string deviceId)
    {
        try
        {
            await (await GetDeviceModuleAsync()).InvokeVoidAsync("removeDeviceKey", deviceId);
            return true;
        }
        catch (Exception exception) when (exception is JSException or JSDisconnectedException or InvalidOperationException)
        {
            return false;
        }
    }

    private async Task<bool> ReconcileLocalKeysAsync()
    {
        try
        {
            var activeDeviceIds = _devices
                .Where(device => device.RevocationState == DeviceRevocationState.Active)
                .Select(device => device.DeviceId)
                .ToArray();
            var result = await (await GetDeviceModuleAsync())
                .InvokeAsync<LocalKeyReconciliation>("reconcileDeviceKeys", activeDeviceIds);
            if (result.Activated > 0)
            {
                SetSuccess(result.Activated == 1
                    ? "Recovered this browser's registered device key after an interrupted activation."
                    : $"Recovered {result.Activated} registered device keys after interrupted activation.");
                return true;
            }
        }
        catch (Exception exception) when (exception is JSException or JSDisconnectedException or InvalidOperationException)
        {
            // Server state remains authoritative; a failed local repair is surfaced only when registration itself fails.
        }

        return false;
    }

    private static string ShortFingerprint(string value) =>
        value.Length <= 28 ? value : $"{value[..18]}…{value[^7..]}";
    private static string TrustLabel(DeviceTrustState state) => state == DeviceTrustState.ProofOfPossessionVerified
        ? "Private-key proof verified"
        : "Proof unavailable";
    private static string PlatformLabel(DevicePlatformType platform) => platform switch
    {
        DevicePlatformType.BrowserExtension => "Browser profile",
        DevicePlatformType.SecondLifeHud => "Second Life HUD",
        _ => "HIP client"
    };
    private static string StatusLabel(DeviceRevocationState state) =>
        state == DeviceRevocationState.Active ? "Active" : "Revoked";
    private static string StatusTone(DeviceRevocationState state) =>
        state == DeviceRevocationState.Active ? "active" : "revoked";
    private static string FormatDate(DateTimeOffset value) =>
        value.UtcDateTime.ToString("MMM d, yyyy · HH:mm 'UTC'");
    private static string FormatRevokedDate(DateTimeOffset? value) =>
        value is null ? "Revoked" : $"Revoked {FormatDate(value.Value)}";

    private static string BrowserSupportFailure(BrowserDeviceSupport? support)
    {
        if (support is null) return "HIP could not inspect this browser's secure key features. Refresh and try again.";
        if (!support.SecureContext) return "Device registration requires a secure HTTPS or localhost page.";
        if (!support.WebCryptoAvailable) return "This browser does not provide the WebCrypto features HIP needs for a non-exportable key.";
        if (!support.KeyStorageAvailable) return "This browser profile is blocking local device-key storage. Allow site data for HIP, then refresh.";
        return "Secure device registration is unavailable in this browser profile.";
    }

    private static string BrowserRegistrationError(string message, string stage)
    {
        if (message.Contains("HIP_DEVICE_INSECURE_CONTEXT", StringComparison.Ordinal))
            return "Registration stopped because this is not a secure HTTPS or localhost page.";
        if (message.Contains("HIP_DEVICE_WEBCRYPTO_UNAVAILABLE", StringComparison.Ordinal))
            return "Registration stopped because WebCrypto is unavailable in this browser.";
        if (message.Contains("HIP_DEVICE_KEY_STORAGE_UNAVAILABLE", StringComparison.Ordinal))
            return "Registration stopped because this browser profile could not retain the private key. Allow site data for HIP, then retry.";
        return $"Registration stopped while {stage}. HIP did not send the private key to the server; retry or refresh the page.";
    }

    public async ValueTask DisposeAsync()
    {
        if (_deviceModule is null) return;
        try { await _deviceModule.DisposeAsync(); }
        catch (JSDisconnectedException) { }
    }

    private sealed record PreparedDeviceKey(
        [property: JsonPropertyName("handle")] string Handle,
        [property: JsonPropertyName("publicKey")] string PublicKey);

    private sealed record LocalKeyReconciliation(
        [property: JsonPropertyName("activated")] int Activated,
        [property: JsonPropertyName("removed")] int Removed);

    private sealed record BrowserDeviceSupport(
        [property: JsonPropertyName("supported")] bool Supported,
        [property: JsonPropertyName("secureContext")] bool SecureContext,
        [property: JsonPropertyName("webCryptoAvailable")] bool WebCryptoAvailable,
        [property: JsonPropertyName("keyStorageAvailable")] bool KeyStorageAvailable,
        [property: JsonPropertyName("extensionAvailable")] bool ExtensionAvailable);
}
