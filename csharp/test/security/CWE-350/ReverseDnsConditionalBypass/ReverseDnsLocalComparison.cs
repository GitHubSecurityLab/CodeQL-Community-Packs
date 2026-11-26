using System;
using System.Net;

// A reverse lookup compared with a host name held in a local variable.
public class ReverseDnsLocalComparison
{
    // BAD: the guarded action is not sensitive, so this is a known false negative.
    public void Bad()
    {
        string secretHostname = "www.domain.nonexistenttld";
        IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
        IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress);
        // The guarded action only prints a message, which is not modeled as a sensitive
        // action by `cs/user-controlled-bypass`, so the condition is not a sink.
        if (hostInfo.HostName.Equals(secretHostname)) // BAD: not reported (false negative)
        {
            Console.WriteLine("Access granted.");
        }
    }

    // BAD: same source, but the guarded action is an authorization method.
    public void BadWithAuthorize(string user)
    {
        string secretHostname = "www.domain.nonexistenttld";
        IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
        IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress); // source
        if (hostInfo.HostName.Equals(secretHostname)) // BAD: reported
        {
            AuthorizeUser(user);
        }
    }

    // GOOD: the host name is only printed, no sensitive action depends on it.
    public void Good()
    {
        string secretHostname = "www.domain.nonexistenttld";
        IPAddress hostIPAddress = IPAddress.Parse("127.0.0.1");
        IPHostEntry hostInfo = Dns.GetHostEntry(hostIPAddress);
        if (hostInfo.HostName.Equals(secretHostname))
        {
            Console.WriteLine(hostInfo.HostName);
        }
    }

    private static void AuthorizeUser(string user) { }
}
