namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Requires one versioned record to remain at an exact version until an atomic aggregate write
/// commits. Expected version zero means the record must remain absent.
/// </summary>
public sealed record HipVersionedRecordGuard(
    string Partition,
    string Id,
    long ExpectedVersion);

/// <summary>
/// Describes an encrypted record that must commit in the same transaction as a versioned HIP aggregate.
/// The non-generic base lets one transaction safely carry different payload types without erasing
/// their compile-time serialization contracts.
/// </summary>
public abstract class HipRelatedRecordWrite
{
    /// <summary>Initializes a related encrypted record descriptor.</summary>
    protected HipRelatedRecordWrite(string partition, string id)
    {
        Partition = partition;
        Id = id;
    }

    /// <summary>Gets the logical encrypted-record partition.</summary>
    public string Partition { get; }

    /// <summary>Gets the stable record identifier.</summary>
    public string Id { get; }

    internal abstract bool HasValue { get; }

    internal abstract string SerializeValue();
}

/// <summary>
/// Describes a typed encrypted record that must commit with a versioned HIP aggregate.
/// </summary>
/// <typeparam name="T">Related record payload type.</typeparam>
public sealed class HipRelatedRecordWrite<T> : HipRelatedRecordWrite
{
    /// <summary>Initializes a typed related record descriptor.</summary>
    public HipRelatedRecordWrite(string partition, string id, T value)
        : base(partition, id)
    {
        Value = value;
    }

    /// <summary>Gets the typed record payload.</summary>
    public T Value { get; }

    internal override bool HasValue => Value is not null;

    internal override string SerializeValue() => HipJsonSerializer.Serialize(Value);
}
