using System.Text.Json;
using HIP.Admin.Models;
using Microsoft.JSInterop;

namespace HIP.Admin.Services;

public sealed class ThemeService
{
    private const string StorageKey = "hip.admin.theme";
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

        // Normalize legacy presets to King baseline (prevents old blue skins from overriding current palette).
        if (!Presets.Any(p => p.Key == State.PresetKey) || State.PresetKey == "ocean" || State.PresetKey == "royal")
        {
            State.PresetKey = "king";
            State.DarkMode = false;
            State.BrightMode = false;
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

    public async Task SetDarkModeAsync(bool enabled)
    {
        State.DarkMode = enabled;
        if (enabled) State.BrightMode = false;
        await PersistAndApplyAsync();
    }

    public async Task SetBrightModeAsync(bool enabled)
    {
        State.BrightMode = enabled;
        if (enabled) State.DarkMode = false;
        await PersistAndApplyAsync();
    }

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
        await _js.InvokeVoidAsync("hipTheme.apply", preset, State.DarkMode, State.BrightMode);
        Changed?.Invoke();
    }
}
