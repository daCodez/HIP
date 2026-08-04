using HIP.Application.ServiceClients;
using HIP.Domain.ServiceClients;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;

namespace HIP.Web.Components.Pages;

/// <summary>Coordinates owner-bound service-client management without retaining credentials outside component memory.</summary>
public partial class AdminApiDeveloper : IDisposable
{
    private const int PageSize = 50;
    private const string StepUpHref = "/step-up?returnUrl=%2Fadmin%2Fapi";
    private static readonly string[] MutationPolicies =
    [
        AdminPolicies.CanManageServiceClients,
        AdminPolicies.RecentPrivilegedAuthentication
    ];

    [Inject] private IServiceClientLifecycleService LifecycleService { get; set; } = default!;
    [Inject] private AuthenticationStateProvider AuthenticationStateProvider { get; set; } = default!;
    [Inject] private IAuthorizationService AuthorizationService { get; set; } = default!;
    [Inject] private IHostEnvironment HostEnvironment { get; set; } = default!;

    private readonly List<ServiceClientResponse> _clients = [];
    private string _displayName = string.Empty;
    private string _selectedScope = ServiceClientScopeValues.DomainVerificationCheck;
    private string _domainGrantsText = string.Empty;
    private int _lifetimeDays = ServiceClientRegistrationLimits.DefaultLifetimeDays;
    private string? _nextCursor;
    private string? _oneTimeCredential;
    private string? _errorMessage;
    private string? _statusMessage;
    private string? _confirmingClientId;
    private bool _requiresStepUp;
    private bool _isLoading = true;
    private bool _isBusy;

    private bool CreateDisabled =>
        _isBusy ||
        string.IsNullOrWhiteSpace(_displayName) ||
        string.IsNullOrWhiteSpace(_domainGrantsText) ||
        _lifetimeDays is < ServiceClientRegistrationLimits.MinimumLifetimeDays or
            > ServiceClientRegistrationLimits.MaximumLifetimeDays;

    /// <summary>Loads the first owner-scoped registration page.</summary>
    protected override Task OnInitializedAsync() => LoadClientsAsync();

    private Task LoadClientsAsync() => LoadClientsAsync(append: false);

    private Task LoadMoreAsync() => LoadClientsAsync(append: true);

    private async Task LoadClientsAsync(bool append)
    {
        if (_isLoading && append)
        {
            return;
        }

        _isLoading = true;
        ResetMessages();
        try
        {
            var authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
            var authorization = await AuthorizationService.AuthorizeAsync(
                authenticationState.User,
                null,
                AdminPolicies.CanViewServiceClients);
            if (!authorization.Succeeded ||
                !HipAuthenticatedIdentity.TryResolveUniqueClaim(
                    authenticationState.User,
                    HipAuthenticationClaimTypes.ActorId,
                    out var owner))
            {
                _errorMessage = HipAdminPageAccess.AccessUnavailableMessage;
                return;
            }

            var result = await LifecycleService.ListAsync(
                owner,
                append ? _nextCursor : null,
                PageSize,
                CancellationToken.None);
            if (result.Outcome != ServiceClientLifecycleOutcome.Succeeded)
            {
                _errorMessage = SafeMessage(result.Outcome);
                return;
            }

            if (!append)
            {
                _clients.Clear();
            }

            foreach (var client in result.Items)
            {
                Upsert(client);
            }

            _nextCursor = result.NextCursor;
        }
        catch (Exception)
        {
            _errorMessage = ServiceClientLifecycleMessages.Unavailable;
        }
        finally
        {
            _isLoading = false;
        }
    }

    private async Task CreateClientAsync()
    {
        if (CreateDisabled)
        {
            return;
        }

        _isBusy = true;
        ResetMessages();
        try
        {
            var request = new CreateServiceClientRequest(
                _displayName,
                [_selectedScope],
                ParseDomainGrants(),
                _lifetimeDays);
            var access = await ExecuteMutationAsync((actor, cancellationToken) =>
                LifecycleService.CreateAsync(actor, actor, request, cancellationToken));
            if (!RequireMutationAccess(access))
            {
                return;
            }

            var result = access.Value!;
            if (result.Outcome != ServiceClientLifecycleOutcome.Succeeded || result.Registration is null)
            {
                _errorMessage = SafeMessage(result.Outcome);
                return;
            }

            ShowOneTimeCredential(result.Registration);
            Upsert(result.Registration.Client);
            _statusMessage = "Service client created. Copy the one-time credential before dismissing it.";
            _displayName = string.Empty;
            _domainGrantsText = string.Empty;
        }
        catch (Exception)
        {
            _errorMessage = ServiceClientLifecycleMessages.Unavailable;
        }
        finally
        {
            _isBusy = false;
        }
    }

    private async Task RotateAsync(ServiceClientResponse client)
    {
        if (_isBusy || client.Status != ServiceClientStatus.Active || IsExpired(client))
        {
            return;
        }

        _isBusy = true;
        ResetMessages();
        try
        {
            var access = await ExecuteMutationAsync((actor, cancellationToken) =>
                LifecycleService.RotateCredentialAsync(actor, actor, client.ClientId, client.AggregateVersion, cancellationToken));
            if (!RequireMutationAccess(access))
            {
                return;
            }

            var result = access.Value!;
            if (result.Outcome != ServiceClientLifecycleOutcome.Succeeded || result.Registration is null)
            {
                _errorMessage = SafeMessage(result.Outcome);
                return;
            }

            ShowOneTimeCredential(result.Registration);
            Upsert(result.Registration.Client);
            _statusMessage = "Credential rotated. Copy the replacement credential now; the previous credential no longer authenticates.";
        }
        catch (Exception)
        {
            _errorMessage = ServiceClientLifecycleMessages.Unavailable;
        }
        finally
        {
            _isBusy = false;
        }
    }

    private async Task RevokeAsync(ServiceClientResponse client)
    {
        if (_isBusy || client.Status != ServiceClientStatus.Active)
        {
            return;
        }

        _isBusy = true;
        ResetMessages();
        try
        {
            var access = await ExecuteMutationAsync((actor, cancellationToken) =>
                LifecycleService.RevokeAsync(actor, actor, client.ClientId, client.AggregateVersion, cancellationToken));
            if (!RequireMutationAccess(access))
            {
                return;
            }

            var result = access.Value!;
            if (result.Outcome != ServiceClientLifecycleOutcome.Succeeded || result.Client is null)
            {
                _errorMessage = SafeMessage(result.Outcome);
                return;
            }

            Upsert(result.Client);
            _oneTimeCredential = null;
            _confirmingClientId = null;
            _statusMessage = "Service client revoked. Revocation is terminal.";
        }
        catch (Exception)
        {
            _errorMessage = ServiceClientLifecycleMessages.Unavailable;
        }
        finally
        {
            _isBusy = false;
        }
    }

    private async Task<HipAdminPageAccessResult<T>> ExecuteMutationAsync<T>(
        Func<string, CancellationToken, Task<T>> operation)
    {
        var authenticationState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
        return await HipAdminPageAccess.ExecuteAuthorizedAsync(
            authenticationState.User,
            AuthorizationService,
            HostEnvironment,
            MutationPolicies,
            operation,
            CancellationToken.None);
    }

    private bool RequireMutationAccess<T>(HipAdminPageAccessResult<T> access)
    {
        if (access.Succeeded && access.Value is not null)
        {
            return true;
        }

        _requiresStepUp = true;
        _errorMessage = "Confirm your identity before changing service-client access.";
        return false;
    }

    private void ShowOneTimeCredential(ServiceClientRegistrationResult registration) =>
        _oneTimeCredential = string.Concat(
            registration.Client.ClientId,
            ".",
            registration.OneTimeSecret.Reveal());

    private void DismissCredential() => _oneTimeCredential = null;

    /// <summary>Drops the component's reference to one-time credential material when the circuit removes the page.</summary>
    public void Dispose() => _oneTimeCredential = null;

    private void BeginRevoke(string clientId) => _confirmingClientId = clientId;

    private void CancelRevoke() => _confirmingClientId = null;

    private void Upsert(ServiceClientResponse client)
    {
        var existing = _clients.FindIndex(candidate =>
            string.Equals(candidate.ClientId, client.ClientId, StringComparison.Ordinal));
        if (existing >= 0)
        {
            _clients[existing] = client;
        }
        else
        {
            _clients.Add(client);
        }

        _clients.Sort((left, right) => right.CreatedAtUtc.CompareTo(left.CreatedAtUtc));
    }

    private IReadOnlyCollection<string> ParseDomainGrants() =>
        _domainGrantsText.Split(
            [',', ';', '\r', '\n'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private void ResetMessages()
    {
        _errorMessage = null;
        _statusMessage = null;
        _requiresStepUp = false;
    }

    private static string SafeMessage(ServiceClientLifecycleOutcome outcome) => outcome switch
    {
        ServiceClientLifecycleOutcome.InvalidRequest => ServiceClientLifecycleMessages.InvalidRequest,
        ServiceClientLifecycleOutcome.NotFound => ServiceClientLifecycleMessages.ResourceUnavailable,
        ServiceClientLifecycleOutcome.Conflict => ServiceClientLifecycleMessages.Conflict,
        ServiceClientLifecycleOutcome.Expired => ServiceClientLifecycleMessages.Expired,
        ServiceClientLifecycleOutcome.Revoked => ServiceClientLifecycleMessages.Revoked,
        ServiceClientLifecycleOutcome.Throttled => ServiceClientLifecycleMessages.Throttled,
        _ => ServiceClientLifecycleMessages.Unavailable
    };

    private static bool IsExpired(ServiceClientResponse client) => client.ExpiresAtUtc <= DateTimeOffset.UtcNow;

    private static string StatusLabel(ServiceClientResponse client) =>
        client.Status == ServiceClientStatus.Revoked
            ? "Revoked"
            : IsExpired(client)
                ? "Expired"
                : "Active";

    private static string StatusTone(ServiceClientResponse client) =>
        client.Status == ServiceClientStatus.Revoked
            ? "revoked"
            : IsExpired(client)
                ? "expired"
                : "active";

    private static string FormatDate(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'") ?? "-";
}
