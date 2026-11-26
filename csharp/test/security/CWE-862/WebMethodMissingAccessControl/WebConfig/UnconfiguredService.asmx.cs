using System.Web.Services;

namespace Bank.WebServices
{
    public class UnconfiguredService : WebService
    {
        // BAD: no `<location>` rule in Web.config covers this service.
        [WebMethod]
        public void TransferFunds()
        {
            System.Console.WriteLine("transfer");
        }
    }
}
