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

        return address.AddressFamily == AddressFamily.InterNetworkV6 &&
            !address.IsIPv6LinkLocal && !address.IsIPv6Multicast && !address.IsIPv6SiteLocal &&
            (bytes[0] & 0xFE) != 0xFC &&
            !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8);
    }
}
