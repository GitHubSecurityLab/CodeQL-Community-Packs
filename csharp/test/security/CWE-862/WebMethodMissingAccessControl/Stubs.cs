// Minimal stubs for the ASP.NET (System.Web) types used by the tests.
namespace System.Web
{
    public class HttpContext
    {
        public System.Security.Principal.IPrincipal User => throw null;
    }
}

namespace System.Web.Services
{
    public class WebMethodAttribute : System.Attribute
    {
        public string Description { get; set; }
    }

    public class WebServiceAttribute : System.Attribute
    {
        public string Namespace { get; set; }
        public string Description { get; set; }
    }

    public class WebService
    {
        public System.Web.HttpContext Context => throw null;
    }
}

namespace System.Web.UI
{
    public class Page
    {
        public System.Web.HttpContext Context => throw null;
    }
}

namespace System.Web.Mvc
{
    public class AuthorizeAttribute : System.Attribute { }
}

namespace System.Web.Http
{
    public class AuthorizeAttribute : System.Attribute { }
}
