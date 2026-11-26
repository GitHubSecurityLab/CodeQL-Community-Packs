using System.Web.Mvc;
using System.Web.Services;

namespace Bank.WebServices
{
    public class RequireAuthorizationAttribute : System.Attribute { }

    [WebService(Namespace = "http://example.com/")]
    public class AccountService : WebService
    {
        // BAD: state-changing web method without any authorization check.
        [WebMethod]
        public string TransferBalance(long from, long to, double amount)
        {
            Withdraw(from, amount);
            Deposit(to, amount);
            return "OK";
        }

        // BAD: edit operation exposed as a web method without authorization.
        [WebMethod]
        public void DeleteAccount(long accountId)
        {
            Remove(accountId);
        }

        // BAD: `update` is a whole camelCase word of the name.
        [WebMethod]
        public void UpdateEmail(long accountId, string email)
        {
            System.Console.WriteLine(accountId + email);
        }

        // GOOD: checks that the caller is authenticated.
        [WebMethod]
        public string TransferBalanceChecked(long from, long to, double amount)
        {
            if (!Context.User.Identity.IsAuthenticated)
                return "Unauthorized";
            Withdraw(from, amount);
            Deposit(to, amount);
            return "OK";
        }

        // GOOD: checks the caller's role.
        [WebMethod]
        public void DeleteAccountChecked(long accountId)
        {
            if (Context.User.IsInRole("Admin"))
                Remove(accountId);
        }

        // GOOD: an authorization attribute that is not an MVC or Web API filter.
        [WebMethod]
        [RequireAuthorization]
        public void WithdrawAll(long accountId)
        {
            Withdraw(accountId, 0);
        }

        // BAD: MVC authorization attributes do not protect ASMX operations.
        [WebMethod]
        [Authorize]
        public string TransferBalanceAuthorized(long from, long to, double amount)
        {
            Withdraw(from, amount);
            Deposit(to, amount);
            return "OK";
        }

        // BAD: Web API authorization attributes do not protect ASMX operations.
        [WebMethod]
        [System.Web.Http.Authorize]
        public void DepositAll(long accountId)
        {
            Deposit(accountId, 0);
        }

        // GOOD: read-only operation, the query only targets sensitive (state-changing / admin) actions.
        [WebMethod]
        public long[] GetUserAccounts(long userId)
        {
            return new long[] { userId };
        }

        // GOOD: `updated` is not the whole word `update`.
        [WebMethod]
        public string GetLastUpdated(long accountId)
        {
            return accountId.ToString();
        }

        // GOOD: not a web method, so not remotely invocable.
        public void TransferInternal(long from, long to, double amount)
        {
            Withdraw(from, amount);
            Deposit(to, amount);
        }

        // GOOD: empty web method.
        [WebMethod]
        public void TransferNothing() { }

        private void Withdraw(long account, double amount) { }

        private void Deposit(long account, double amount) { }

        private void Remove(long account) { }
    }

    [Authorize]
    public class AdminService : WebService
    {
        // BAD: MVC authorization attributes do not protect ASMX operations.
        [WebMethod]
        public void DeleteUser(long userId)
        {
            System.Console.WriteLine(userId);
        }
    }

    [RequireAuthorization]
    public class ProtectedService : WebService
    {
        // GOOD: the class has an authorization attribute that applies to its web methods.
        [WebMethod]
        public void RemoveUser(long userId)
        {
            System.Console.WriteLine(userId);
        }
    }

    public class TransfersPage : System.Web.UI.Page
    {
        // BAD: ASP.NET page method (static [WebMethod]) without authorization.
        [WebMethod]
        public static void TransferFunds(long from, long to, double amount)
        {
            System.Console.WriteLine(from + to + amount);
        }
    }
}
