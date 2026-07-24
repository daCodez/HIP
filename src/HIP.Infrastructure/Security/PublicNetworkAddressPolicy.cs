using System.Net;
using System.Net.Sockets;

namespace HIP.Infrastructure.Security;

/// <summary>Shared fail-closed classification for server-side connections to public Internet addresses.</summary>
public static class PublicNetworkAddressPolicy
{
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] switch
            {
                0 or 10 or 127 => false,
                100 when bytes[1] is >= 64 and <= 127 => false,
                169 when bytes[1] == 254 => false,
                172 when bytes[1] is >= 16 and <= 31 => false,
                192 when bytes[1] == 0 && bytes[2] is 0 or 2 => false,
                192 when bytes[1] == 88 && bytes[2] == 99 => false,
                192 when bytes[1] == 168 => false,
                198 when bytes[1] is 18 or 19 => false,
                198 when bytes[1] == 51 && bytes[2] == 100 => false,
                203 when bytes[1] == 0 && bytes[2] == 113 => false,
                >= 224 => false,
                _ => true
            };
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6 ||
            address.IsIPv6LinkLocal ||
            address.IsIPv6Multicast ||
            address.IsIPv6SiteLocal ||
            (bytes[0] & 0xFE) == 0xFC)
        {
            return false;
        }

        // Fail closed outside IANA's currently allocated global-unicast 2000::/3 block.
        if ((bytes[0] & 0xE0) != 0x20)
        {
            return false;
        }

        return !IsPrefix(bytes, 0x20, 0x01, 0x00, 0x00) && // Teredo and special 2001:0000::/32
            !IsPrefix(bytes, 0x20, 0x01, 0x00, 0x02) && // Benchmarking 2001:2::/48
            !IsPrefix(bytes, 0x20, 0x01, 0x0d, 0xb8) && // Documentation 2001:db8::/32
            !(bytes[0] == 0x20 && bytes[1] == 0x02) && // 6to4 can tunnel embedded private IPv4
            !(bytes[0] == 0x3f && bytes[1] == 0xfe) && // Retired 6bone range
            !(bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xF0) == 0); // Documentation 3fff::/20
    }

    private static bool IsPrefix(byte[] address, byte first, byte second, byte third, byte fourth) =>
        address[0] == first && address[1] == second && address[2] == third && address[3] == fourth;
}
