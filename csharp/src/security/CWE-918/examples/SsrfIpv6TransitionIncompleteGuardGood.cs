using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

public class GoodFetcher
{
    // GOOD: the guard parses the host and unwraps every IPv6-transition family to its
    // embedded IPv4 address before applying the private-range check. NAT64 `64:ff9b::/96`,
    // 6to4 `2002::/16` and IPv4-mapped `::ffff:` are all canonicalized, so an internal
    // address wrapped in any transition literal is detected.
    private static IPAddress UnwrapTransition(IPAddress addr)
    {
        byte[] b = addr.GetAddressBytes();
        // NAT64 well-known prefix 64:ff9b::/96 -> last 4 bytes are the embedded IPv4. The full
        // /96 must be matched: bytes 0..3 are 00 64 ff 9b and bytes 4..11 are all zero, so an
        // address that merely starts with 64:ff9b but carries non-zero middle bytes is not
        // mistaken for a NAT64 address and is left unwrapped.
        if (b.Length == 16 && b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b
            && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0
            && b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0)
        {
            return new IPAddress(new[] { b[12], b[13], b[14], b[15] });
        }
        // 6to4 2002::/16 -> bytes 2..5 are the embedded IPv4.
        if (b.Length == 16 && b[0] == 0x20 && b[1] == 0x02)
        {
            return new IPAddress(new[] { b[2], b[3], b[4], b[5] });
        }
        // IPv4-mapped ::ffff:0:0/96.
        if (addr.IsIPv4MappedToIPv6)
        {
            return addr.MapToIPv4();
        }
        return addr;
    }

    private static bool IsPrivateHost(string host)
    {
        IPAddress addr = UnwrapTransition(IPAddress.Parse(host));
        byte[] b = addr.GetAddressBytes();
        return b.Length == 4
            && (b[0] == 127 || b[0] == 10 || (b[0] == 169 && b[1] == 254)
                || (b[0] == 192 && b[1] == 168)
                // Full RFC 1918 172.16.0.0/12 range: second octet 16..31.
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31));
    }

    public static async Task<string> FetchAsync(string host)
    {
        if (IsPrivateHost(host))
        {
            throw new Exception("blocked internal host");
        }

        using var client = new HttpClient();
        return await client.GetStringAsync("http://" + host + "/");
    }
}
