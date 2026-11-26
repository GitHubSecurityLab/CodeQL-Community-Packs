namespace Bank
{
    using System;
    using System.Web.Services;

    public struct TransferResult
    {
        public bool Success;
        public string Message;
    }

    // Variant: SOAP service in App_Code with a fully qualified base type and
    // `[WebMethod(Description = ...)]` named arguments, taking a request object.
    [WebService(Namespace = "http://example.com/bank/ws/", Description = "Core bank services.")]
    public class Services : System.Web.Services.WebService
    {
        public class MoneyTransfer
        {
            public string debitAccount;
            public string creditAccount;
            public double transferAmount;

            public bool setAmount(double amt)
            {
                this.transferAmount = amt;
                return true;
            }
        }

        // GOOD: read-only lookup (not considered sensitive by name).
        [WebMethod(Description = "Determine if a UserId is valid and exists.")]
        public bool IsValidUser(string userId)
        {
            return userId.Length > 0;
        }

        // GOOD: read-only lookup (not considered sensitive by name).
        [WebMethod(Description = "Retrieve accounts by UserId.")]
        public int[] GetUserAccounts(int userId)
        {
            return new int[] { userId };
        }

        // BAD: anonymous callers can move funds between arbitrary accounts.
        [WebMethod(Description = "Transfer funds from one account to another.")]
        public TransferResult TransferBalance(MoneyTransfer transDetails)
        {
            TransferResult result = new TransferResult();
            result.Success = transDetails.debitAccount != transDetails.creditAccount;
            result.Message = "$" + transDetails.transferAmount + " transferred.";
            return result;
        }
    }
}
