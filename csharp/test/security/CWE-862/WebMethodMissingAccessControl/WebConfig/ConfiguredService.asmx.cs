using System.Web.Mvc;
using System.Web.Services;

namespace Bank.WebServices
{
    [Authorize]
    public class ConfiguredService : WebService
    {
        // GOOD: the `<location>` rule in Web.config denies anonymous users.
        [WebMethod]
        public void TransferFunds()
        {
            System.Console.WriteLine("transfer");
        }
    }
}
