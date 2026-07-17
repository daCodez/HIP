using System.Globalization;
using System.Text;
using System.Text.Json;
using HIP.Application;
using HIP.Application.Protocol;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

public sealed class Rfc8785CanonicalJsonServiceTests
{
    private readonly Rfc8785CanonicalJsonService service = new();

    [Test]
    public void Rfc_section_3_2_sample_matches_published_canonical_utf8()
    {
        // RFC 8785 sections 3.2.2 and 3.2.3:
        // https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.2
        const string input = """
            {
              "numbers": [333333333.33333329, 1E30, 4.50,
                          2e-3, 0.000000000000000000000000001],
              "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
              "literals": [null, true, false]
            }
            """;
        const string expected = """{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}""";

        var actual = service.Canonicalize(Encoding.UTF8.GetBytes(input));

        Assert.That(actual, Is.EqualTo(Encoding.UTF8.GetBytes(expected)));
    }

    [Test]
    public void Rfc_section_3_2_3_property_names_are_sorted_as_utf16_code_units()
    {
        // This is the published non-ASCII ordering fixture from RFC 8785 section 3.2.3.
        const string input = """
            {
              "\u20ac": "Euro Sign",
              "\r": "Carriage Return",
              "\ufb33": "Hebrew Letter Dalet With Dagesh",
              "1": "One",
              "\ud83d\ude00": "Emoji: Grinning Face",
              "\u0080": "Control",
              "\u00f6": "Latin Small Letter O With Diaeresis"
            }
            """;
        const string expected = """{"\r":"Carriage Return","1":"One","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}""";

        var actual = CanonicalString(input);

        Assert.That(actual, Is.EqualTo(expected));
    }

    [TestCase("0000000000000000", "0")]

    [TestCase("0000000000000001", "5e-324")]
    [TestCase("8000000000000001", "-5e-324")]
    [TestCase("7fefffffffffffff", "1.7976931348623157e+308")]
    [TestCase("ffefffffffffffff", "-1.7976931348623157e+308")]
    [TestCase("4340000000000000", "9007199254740992")]
    [TestCase("c340000000000000", "-9007199254740992")]
    [TestCase("4430000000000000", "295147905179352830000")]
    [TestCase("44b52d02c7e14af5", "9.999999999999997e+22")]
    [TestCase("44b52d02c7e14af6", "1e+23")]
    [TestCase("44b52d02c7e14af7", "1.0000000000000001e+23")]
    [TestCase("444b1ae4d6e2ef4e", "999999999999999700000")]
    [TestCase("444b1ae4d6e2ef4f", "999999999999999900000")]
    [TestCase("444b1ae4d6e2ef50", "1e+21")]
    [TestCase("3eb0c6f7a0b5ed8c", "9.999999999999997e-7")]
    [TestCase("3eb0c6f7a0b5ed8d", "0.000001")]
    [TestCase("41b3de4355555553", "333333333.3333332")]
    [TestCase("41b3de4355555554", "333333333.33333325")]
    [TestCase("41b3de4355555555", "333333333.3333333")]
    [TestCase("41b3de4355555556", "333333333.3333334")]
    [TestCase("41b3de4355555557", "333333333.33333343")]
    [TestCase("becbf647612f3696", "-0.0000033333333333333333")]
    [TestCase("43143ff3c1cb0959", "1424953923781206.2")]
    public void Rfc_appendix_b_finite_number_vectors_match(string ieee754, string expected)
    {
        var bits = unchecked((long)Convert.ToUInt64(ieee754, 16));
        var value = BitConverter.Int64BitsToDouble(bits);
        var input = value.ToString("R", CultureInfo.InvariantCulture);

        var actual = CanonicalString(input);

        Assert.That(actual, Is.EqualTo(expected));
    }

    [Test]
    public void Objects_inside_arrays_are_sorted_recursively_without_reordering_array_items()
    {
        const string input = """[{"z":1,"a":2},{"b":3,"a":4}]""";
        const string expected = """[{"a":2,"z":1},{"a":4,"b":3}]""";

        Assert.That(CanonicalString(input), Is.EqualTo(expected));
    }

    [Test]
    public void Strings_use_rfc_escapes_and_preserve_unicode_without_normalization()
    {
        const string input = "{\"precomposed\":\"\u00e9\",\"controls\":\"\\u0000\\u0008\\u0009\\u000a\\u000c\\u000d\\/\\u2028\",\"decomposed\":\"e\u0301\"}";
        const string expected = "{\"controls\":\"\\u0000\\b\\t\\n\\f\\r/\u2028\",\"decomposed\":\"e\u0301\",\"precomposed\":\"\u00e9\"}";

        Assert.That(CanonicalString(input), Is.EqualTo(expected));
    }

    [Test]
    public void Hip_envelope_fixture_is_stable_across_runs_and_property_orders()
    {
        var fixturePath = Path.Combine(
            RepositoryRoot(), "tests", "HIP.Tests", "Protocol", "Fixtures", "hip-envelope-v1.json");
        var canonicalPath = Path.Combine(
            RepositoryRoot(), "tests", "HIP.Tests", "Protocol", "Fixtures", "hip-envelope-v1.canonical.json");
        var input = File.ReadAllBytes(fixturePath);
        var reordered = ReverseObjectProperties(input);
        var expected = File.ReadAllBytes(canonicalPath);

        var first = service.Canonicalize(input);
        var second = service.Canonicalize(input);
        var fromReorderedInput = service.Canonicalize(reordered);

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.EqualTo(expected));
            Assert.That(second, Is.EqualTo(expected));
            Assert.That(fromReorderedInput, Is.EqualTo(expected));
        });
    }

    [TestCase("")]
    [TestCase("{")]
    [TestCase("null true")]
    [TestCase("{/*comment*/\"value\":1}")]
    [TestCase("{\"value\":1,}")]
    [TestCase("{\"value\":1,\"value\":2}")]
    [TestCase("{\"value\":1,\"\\u0076alue\":2}")]
    [TestCase("{\"number\":1e400}")]
    [TestCase("{\"number\":1e-400}")]
    [TestCase("{\"text\":\"\\ud800\"}")]
    [TestCase("{\"text\":\"\ufdd0\"}")]
    [TestCase("{\"\ufffe\":true}")]
    [TestCase("{\"text\":\"\\udbff\\udfff\"}")]
    public void Malformed_or_non_ijson_input_fails_closed(string input)
    {
        Assert.Catch<JsonException>(() => service.Canonicalize(Encoding.UTF8.GetBytes(input)));
    }

    [Test]
    public void Invalid_utf8_fails_closed()
    {
        var input = new byte[] { (byte)'"', 0xc3, 0x28, (byte)'"' };

        Assert.Catch<JsonException>(() => service.Canonicalize(input));
    }

    [TestCase("0e1")]
    [TestCase("0E+10")]
    [TestCase("0.0e2")]
    public void Zero_with_nonzero_exponent_is_not_mistaken_for_underflow(string input)
    {
        Assert.That(CanonicalString(input), Is.EqualTo("0"));
    }

    [TestCase("-0")]
    [TestCase("-0.0")]
    [TestCase("-0e100")]
    public void Negative_zero_fails_closed_per_verified_rfc_errata(string input)
    {
        // RFC 8785 verified technical erratum 7920 recommends rejecting lexical negative zero.
        Assert.Catch<JsonException>(() => service.Canonicalize(Encoding.UTF8.GetBytes(input)));
    }

    [Test]
    public void Input_and_output_are_bounded_to_protocol_limits()
    {
        var oversizedInput = new byte[Rfc8785CanonicalJsonService.MaximumCanonicalJsonBytes + 1];
        var expandingInput = "[" + string.Join(',', Enumerable.Repeat("1e20", 4_000)) + "]";

        Assert.Multiple(() =>
        {
            Assert.Catch<JsonException>(() => service.Canonicalize(oversizedInput));
            Assert.That(Encoding.UTF8.GetByteCount(expandingInput), Is.LessThan(Rfc8785CanonicalJsonService.MaximumCanonicalJsonBytes));
            Assert.Catch<JsonException>(() => service.Canonicalize(Encoding.UTF8.GetBytes(expandingInput)));
        });
    }

    [Test]
    public void Excessive_nesting_fails_closed()
    {
        var input = "true";
        for (var index = 0; index <= Rfc8785CanonicalJsonService.MaximumJsonDepth; index++)
        {
            input = $"[{input}]";
        }

        Assert.Catch<JsonException>(() => service.Canonicalize(Encoding.UTF8.GetBytes(input)));
    }

    [Test]
    public void Application_registration_exposes_canonicalizer_only_through_its_interface()
    {
        var services = new ServiceCollection();
        services.AddHipApplication();
        using var provider = services.BuildServiceProvider();

        var canonicalizer = provider.GetRequiredService<ICanonicalJsonService>();

        Assert.That(canonicalizer, Is.TypeOf<Rfc8785CanonicalJsonService>());
    }

    private string CanonicalString(string input) =>
        Encoding.UTF8.GetString(service.Canonicalize(Encoding.UTF8.GetBytes(input)));

    private static byte[] ReverseObjectProperties(byte[] input)
    {
        using var document = JsonDocument.Parse(input);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var property in document.RootElement.EnumerateObject().Reverse())
            {
                property.WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
