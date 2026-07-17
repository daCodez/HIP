using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using HIP.Application.Protocol;

namespace HIP.Tests.Protocol;

public sealed class Rfc8785ExtendedNumberCorpusTests
{
    private const ulong NegativeZeroBits = 0x8000000000000000UL;
    private const string OfficialFirstThousandSha256 =
        "be18b62b6f69cdab33a7e0dae0d9cfa869fda80ddc712221570f9f40a5878687";

    private static readonly ulong[] NegativeMagnitudeBits =
    [
        0xc46696695dbd1cc3UL, 0xc43211ede4974a35UL, 0xc3fce97ca0f21056UL, 0xc3c7213080c1a6acUL,
        0xc39280f39a348556UL, 0xc35d9b1f5d20d557UL, 0xc327af4c4a80aaacUL, 0xc2f2f2a36ecd5556UL,
        0xc2be51057e155558UL, 0xc28840d131aaaaacUL, 0xc253670dc1555557UL, 0xc21f0b4935555557UL,
        0xc1e8d5d42aaaaaacUL, 0xc1b3de4355555556UL, 0xc17fca0555555556UL, 0xc1496e6aaaaaaaabUL,
        0xc114585555555555UL, 0xc0e046aaaaaaaaabUL, 0xc0aa0aaaaaaaaaaaUL, 0xc074d55555555555UL,
        0xc040aaaaaaaaaaabUL, 0xc00aaaaaaaaaaaabUL, 0xbfd5555555555555UL, 0xbfa1111111111111UL,
        0xbf6b4e81b4e81b4fUL, 0xbf35d867c3ece2a5UL, 0xbf0179ec9cbd821eUL, 0xbecbf647612f3696UL,
        0xbe965e9f80f29212UL, 0xbe61e54c672874dbUL, 0xbe2ca213d840baf8UL, 0xbdf6e80fe033c8c6UL,
        0xbdc2533fe68fd3d2UL, 0xbd8d51ffd74c861cUL, 0xbd5774ccac3d3817UL, 0xbd22c3d6f030f9acUL,
        0xbcee0624b3818f79UL, 0xbcb804ea293472c7UL, 0xbc833721ba905bd3UL, 0xbc4ebe9c5db3c61eUL,
        0xbc18987d17c304e5UL, 0xbbe3ad30dfcf371dUL, 0xbbaf7b816618582fUL, 0xbb792f9ab81379bfUL,
        0xbb442615600f9499UL, 0xbb101e77800c76e1UL, 0xbad9ca58cce0be35UL, 0xbaa4a1e0a3e6fe90UL,
        0xba708180831f320dUL, 0xba3a68cd9e985016UL
    ];

    private static readonly ulong[] TailBits =
    [
        0x4024000000000000UL, 0x4014000000000000UL, 0x3fe0000000000000UL, 0x3fa999999999999aUL,
        0x3f747ae147ae147bUL, 0x3f40624dd2f1a9fcUL, 0x3f0a36e2eb1c432dUL, 0x3ed4f8b588e368f1UL,
        0x3ea0c6f7a0b5ed8dUL, 0x3e6ad7f29abcaf48UL, 0x3e35798ee2308c3aUL, 0x3ed539223589fa95UL,
        0x3ed4ff26cd5a7781UL, 0x3ed4f95a762283ffUL, 0x3ed4f8c60703520cUL, 0x3ed4f8b72f19cd0dUL,
        0x3ed4f8b5b31c0c8dUL, 0x3ed4f8b58d1c461aUL, 0x3ed4f8b5894f7f0eUL, 0x3ed4f8b588ee37f3UL,
        0x3ed4f8b588e47da4UL, 0x3ed4f8b588e3849cUL, 0x3ed4f8b588e36bb5UL, 0x3ed4f8b588e36937UL,
        0x3ed4f8b588e368f8UL, 0x3ed4f8b588e368f1UL, 0x3ff0000000000000UL, 0xbff0000000000000UL,
        0xbfeffffffffffffaUL, 0xbfeffffffffffffbUL, 0x3feffffffffffffaUL, 0x3feffffffffffffbUL,
        0x3feffffffffffffcUL, 0x3feffffffffffffeUL, 0xbfefffffffffffffUL, 0xbfefffffffffffffUL,
        0x3fefffffffffffffUL, 0x3fefffffffffffffUL, 0x3fd3333333333332UL, 0x3fd3333333333333UL,
        0x3fd3333333333334UL, 0x0010000000000000UL, 0x000ffffffffffffdUL, 0x000fffffffffffffUL,
        0x7fefffffffffffffUL, 0xffefffffffffffffUL, 0x4340000000000000UL, 0xc340000000000000UL,
        0x4430000000000000UL, 0x44b52d02c7e14af5UL, 0x44b52d02c7e14af6UL, 0x44b52d02c7e14af7UL,
        0x444b1ae4d6e2ef4eUL, 0x444b1ae4d6e2ef4fUL, 0x444b1ae4d6e2ef50UL, 0x3eb0c6f7a0b5ed8cUL,
        0x3eb0c6f7a0b5ed8dUL, 0x41b3de4355555553UL, 0x41b3de4355555554UL, 0x41b3de4355555555UL,
        0x41b3de4355555556UL, 0x41b3de4355555557UL, 0xbecbf647612f3696UL, 0x43143ff3c1cb0959UL
    ];

    [Test]
    public void Official_extended_es6_number_corpus_prefix_matches_published_hash()
    {
        // The RFC author's deterministic corpus and hashes are published at:
        // https://github.com/cyberphone/json-canonicalization/tree/master/testdata#es6-numbers
        var service = new Rfc8785CanonicalJsonService();
        var corpus = new StringBuilder(40_000);
        var count = 0;

        foreach (var bits in OfficialSequence().Take(1_000))
        {
            var canonical = bits == NegativeZeroBits
                ? "0"
                : Canonicalize(service, BitConverter.Int64BitsToDouble(unchecked((long)bits)));
            corpus.Append(bits.ToString("x", CultureInfo.InvariantCulture));
            corpus.Append(',');
            corpus.Append(canonical);
            corpus.Append('\n');
            count++;
        }

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(corpus.ToString())))
            .ToLowerInvariant();

        Assert.Multiple(() =>
        {
            Assert.That(count, Is.EqualTo(1_000));
            Assert.That(hash, Is.EqualTo(OfficialFirstThousandSha256));
        });
    }

    private static string Canonicalize(Rfc8785CanonicalJsonService service, double value)
    {
        var input = value.ToString("R", CultureInfo.InvariantCulture);
        return Encoding.UTF8.GetString(service.Canonicalize(Encoding.UTF8.GetBytes(input)));
    }

    private static IEnumerable<ulong> OfficialSequence()
    {
        yield return 0x0000000000000000UL;
        yield return NegativeZeroBits;
        yield return 0x0000000000000001UL;
        yield return 0x8000000000000001UL;

        foreach (var bits in NegativeMagnitudeBits)
        {
            yield return bits;
        }

        foreach (var bits in NegativeMagnitudeBits)
        {
            yield return bits & 0x7fffffffffffffffUL;
        }

        foreach (var bits in TailBits)
        {
            yield return bits;
        }

        for (ulong index = 0; index < 2_000; index++)
        {
            yield return 0x0010000000000000UL + index;
        }
    }
}
