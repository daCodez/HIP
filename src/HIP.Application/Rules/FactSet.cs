namespace HIP.Application.Rules;

public sealed record FactSet(IReadOnlyDictionary<string, object?> Values)
{
    public bool TryGetValue(string field, out object? value) => Values.TryGetValue(field, out value);
}
