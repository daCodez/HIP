namespace HIP.Admin.Models;

public sealed class MenuItemModel
{
    public required string Title { get; init; }
    public string? Icon { get; init; }
    public string? Href { get; init; }
    public DateTime? AddedUtc { get; init; }
    public IReadOnlyCollection<AdminRole> VisibleTo { get; init; } = [AdminRole.Admin, AdminRole.Support, AdminRole.Analyst];
    public List<MenuItemModel> Children { get; init; } = [];
}
