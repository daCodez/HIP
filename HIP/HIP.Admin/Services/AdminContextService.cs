using HIP.Admin.Models;

namespace HIP.Admin.Services;

public sealed class AdminContextService
{
    public AdminRole CurrentRole { get; private set; } = AdminRole.Admin;
    public bool MockModeEnabled { get; private set; } = true;

    public event Action? Changed;

    public void SetRole(AdminRole role)
    {
        CurrentRole = role;
        Changed?.Invoke();
    }

    public void SetMockMode(bool enabled)
    {
        MockModeEnabled = enabled;
        Changed?.Invoke();
    }
}
