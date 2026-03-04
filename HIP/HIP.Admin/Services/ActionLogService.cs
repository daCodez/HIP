namespace HIP.Admin.Services;

public sealed class ActionLogService
{
    private readonly List<string> _entries = [];

    public IReadOnlyList<string> Entries => _entries.AsReadOnly();

    public void Log(string action)
    {
        _entries.Insert(0, $"{DateTime.UtcNow:O} | {action}");
        if (_entries.Count > 200)
        {
            _entries.RemoveAt(_entries.Count - 1);
        }
    }
}
