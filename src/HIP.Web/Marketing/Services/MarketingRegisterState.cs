namespace HIP.Web.Marketing.Services;

/// <summary>
/// Controls whether findings are shown in plain language or technical register.
/// One switch, every explanation on the site changes with it.
/// </summary>
public sealed class MarketingRegisterState
{
    public bool Technical { get; private set; }

    public event Action? Changed;

    public void Toggle()
    {
        Technical = !Technical;
        Changed?.Invoke();
    }

    public string Label => Technical ? "Technical" : "Plain language";
}
