namespace HIP.Admin.Models;

public sealed class ThemePreset
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required string Primary { get; init; }
    public required string Accent { get; init; }
    public required string Sidebar { get; init; }
    public required string Surface { get; init; }
}

public sealed class ThemeState
{
    public string PresetKey { get; set; } = "king";
    public bool DarkMode { get; set; }
    public bool BrightMode { get; set; }
}
