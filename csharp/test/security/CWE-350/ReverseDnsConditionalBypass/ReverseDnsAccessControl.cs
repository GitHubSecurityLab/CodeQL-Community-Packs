using System;
using System.Net;
using System.Threading.Tasks;

public class ReverseDnsAccessControl
{
    private const string TrustedHost = "www.domain.nonexistenttld";

    // BAD: reverse DNS of the peer address (GetHostEntry(IPAddress)) decides whether to log in.
    public void GetHostEntryBad(IPAddress peer, string user, string password)
    {
        IPHostEntry hostInfo = Dns.GetHostEntry(peer); // source
        if (hostInfo.HostName.Equals(TrustedHost)) // BAD: reported
        {
            Login(user, password);
        }
    }

    // BAD: reverse DNS with a substring comparison on the host name.
    public void GetHostEntryEndsWithBad(string user, string password)
    {
        IPAddress peer = IPAddress.Parse("127.0.0.1");
        IPHostEntry hostInfo = Dns.GetHostEntry(peer); // source
        if (hostInfo.HostName.EndsWith(".nonexistenttld")) // BAD: reported
        {
            Login(user, password);
        }
    }

    // BAD: asynchronous reverse DNS lookup.
    public async Task GetHostEntryAsyncBad(IPAddress peer, string user, string password)
    {
        IPHostEntry hostInfo = await Dns.GetHostEntryAsync(peer); // source
        if (hostInfo.HostName == TrustedHost) // BAD: reported
        {
            Login(user, password);
        }
    }

    // BAD: obsolete reverse DNS API (already covered by cs/user-controlled-bypass).
    public void GetHostByAddressBad(IPAddress peer, string user, string password)
    {
#pragma warning disable CS0618
        IPHostEntry hostInfo = Dns.GetHostByAddress(peer); // source
#pragma warning restore CS0618
        if (hostInfo.HostName == TrustedHost) // BAD: reported
        {
            Login(user, password);
        }
    }

    // BAD: reverse DNS host name compared with a non-constant (configured) host name.
    public void GetHostEntryConfiguredHostBad(IPAddress peer, string configuredHost, string user, string password)
    {
        IPHostEntry hostInfo = Dns.GetHostEntry(peer); // source
        if (hostInfo.HostName == configuredHost) // BAD: reported
        {
            Login(user, password);
        }
    }

    // GOOD: the reverse DNS host name is only logged, the sensitive action does not depend on it.
    public void GetHostEntryLogOnlyGood(IPAddress peer, string user, string password)
    {
        IPHostEntry hostInfo = Dns.GetHostEntry(peer);
        if (hostInfo.HostName.Equals(TrustedHost))
        {
            Console.WriteLine(hostInfo.HostName);
        }
        Login(user, password);
    }

    // GOOD: authorization decision is based on the peer IP address, not on reverse DNS.
    public void IpAddressAllowListGood(IPAddress peer, string user, string password)
    {
        if (peer.Equals(IPAddress.Loopback))
        {
            Login(user, password);
        }
    }

    // GOOD: forward DNS lookup of a constant host name, compared with the peer address.
    public void ForwardLookupGood(IPAddress peer, string user, string password)
    {
        IPHostEntry trusted = Dns.GetHostEntry(TrustedHost);
        if (Array.IndexOf(trusted.AddressList, peer) >= 0)
        {
            Login(user, password);
        }
    }

    // GOOD: the same sensitive action happens on both branches.
    public void BothBranchesGood(IPAddress peer, string user, string password)
    {
        IPHostEntry hostInfo = Dns.GetHostEntry(peer);
        if (hostInfo.HostName == TrustedHost)
        {
            Login(user, password);
        }
        else
        {
            Login(user, password);
        }
    }

    private static void Login(string user, string password) { }
}
