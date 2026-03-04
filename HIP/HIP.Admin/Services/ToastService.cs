namespace HIP.Admin.Services;

public sealed class ToastService
{
    public event Action<ToastMessage>? OnShow;

    public void Show(string title, string message, string level = "info")
        => OnShow?.Invoke(new ToastMessage(title, message, level));
}

public sealed record ToastMessage(string Title, string Message, string Level);
