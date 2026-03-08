using Microsoft.AspNetCore.Components;

namespace HIP.Admin.Models;

public sealed class FilterFieldOption
{
    public required string Value { get; init; }
    public required string Label { get; init; }
}

public sealed class FilterField
{
    public required string Key { get; init; }
    public required string Label { get; init; }
    public string? Value { get; init; }
    public IReadOnlyList<FilterFieldOption> Options { get; set; } = [];
}

public sealed class FilterBarChangeSet
{
    public string SearchText { get; init; } = string.Empty;
    public IReadOnlyDictionary<string, string?> Values { get; init; } = new Dictionary<string, string?>();
}

public sealed class DataTableColumn<TItem>
{
    public required string Header { get; init; }
    public Func<TItem, object?>? ValueSelector { get; init; }
    public RenderFragment<TItem>? CellTemplate { get; init; }
    public Func<TItem, IComparable?>? SortSelector { get; init; }
    public string? Width { get; init; }
}

public sealed class TabItem
{
    public required string Id { get; init; }
    public required string Label { get; init; }
    public string? Description { get; init; }
    public bool Disabled { get; init; }
    public string? BadgeText { get; init; }
}
