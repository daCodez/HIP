using System.Text.Json;
using HIP.Admin.Models;
using Microsoft.JSInterop;

namespace HIP.Admin.Services;

public sealed class ThemeService
{
    private const string StorageKey = "hip.admin.theme";
    public const string AppearanceSystem = "system";
    public const string AppearanceLight = "light";
    public const string AppearanceDark = "dark";

    private readonly IJSRuntime _js;

    public ThemeService(IJSRuntime js)
    {
        _js = js;
    }

    public ThemeState State { get; private set; } = new();

    public IReadOnlyList<ThemePreset> Presets { get; } =
    [
        new() { Key = "king", Name = "King", Primary = "#23a7c6", Accent = "#23a7c6", Sidebar = "#dcdcdc", Surface = "#eeeeee" },
        new() { Key = "graphite", Name = "Graphite", Primary = "#4c4c4c", Accent = "#23a7c6", Sidebar = "#d7d7d7", Surface = "#eeeeee" },
        new() { Key = "teal", Name = "Teal", Primary = "#1D92AF", Accent = "#23a7c6", Sidebar = "#dcdcdc", Surface = "#efefef" },
        new() { Key = "olive", Name = "Olive", Primary = "#7f9619", Accent = "#7f9619", Sidebar = "#dcdcdc", Surface = "#eeeeee" },
        new() { Key = "amber", Name = "Amber", Primary = "#d88912", Accent = "#d88912", Sidebar = "#dcdcdc", Surface = "#efefef" },
        new() { Key = "slate", Name = "Slate", Primary = "#555555", Accent = "#23a7c6", Sidebar = "#d8d8d8", Surface = "#ededed" }
    ];

    public event Action? Changed;

    public async Task InitializeAsync()
    {
        var raw = await _js.InvokeAsync<string?>("hipTheme.get", StorageKey);
        if (!string.IsNullOrWhiteSpace(raw))
        {
            var saved = JsonSerializer.Deserialize<ThemeState>(raw);
            if (saved is not null)
            {
                State = saved;
            }
        }

        if (string.IsNullOrWhiteSpace(State.Appearance))
        {
            State.Appearance = State.DarkMode ? AppearanceDark : AppearanceLight;
        }

        State.Appearance = NormalizeAppearance(State.Appearance);
        State.DarkMode = State.Appearance == AppearanceDark;
        State.BrightMode = State.Appearance == AppearanceLight;

        // Normalize legacy presets to King baseline (prevents old blue skins from overriding current palette).
        if (!Presets.Any(p => p.Key == State.PresetKey) || State.PresetKey == "ocean" || State.PresetKey == "royal")
        {
            State.PresetKey = "king";
            var json = JsonSerializer.Serialize(State);
            await _js.InvokeVoidAsync("hipTheme.set", StorageKey, json);
        }

        await ApplyAsync();
    }

    public async Task SetPresetAsync(string key)
    {
        State.PresetKey = key;
        await PersistAndApplyAsync();
    }

    public async Task SetAppearanceAsync(string appearance)
    {
        State.Appearance = NormalizeAppearance(appearance);
        State.DarkMode = State.Appearance == AppearanceDark;
        State.BrightMode = State.Appearance == AppearanceLight;
        await PersistAndApplyAsync();
    }

    public Task SetDarkModeAsync(bool enabled)
        => SetAppearanceAsync(enabled ? AppearanceDark : AppearanceSystem);

    public Task SetBrightModeAsync(bool enabled)
        => SetAppearanceAsync(enabled ? AppearanceLight : AppearanceSystem);

    public async Task ResetAsync()
    {
        State = new ThemeState();
        await PersistAndApplyAsync();
    }

    private async Task PersistAndApplyAsync()
    {
        var json = JsonSerializer.Serialize(State);
        await _js.InvokeVoidAsync("hipTheme.set", StorageKey, json);
        await ApplyAsync();
    }

    private async Task ApplyAsync()
    {
        var preset = Presets.FirstOrDefault(x => x.Key == State.PresetKey) ?? Presets[0];
        await _js.InvokeVoidAsync("hipTheme.apply", preset, State.Appearance);
        Changed?.Invoke();
    }

    private static string NormalizeAppearance(string? appearance)
        => appearance?.ToLowerInvariant() switch
        {
            AppearanceLight => AppearanceLight,
            AppearanceDark => AppearanceDark,
            _ => AppearanceSystem
        };
}
