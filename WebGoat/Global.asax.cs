using System;
using System.Collections.Generic;
using System.Web;
using System.Web.Security;
using System.Web.SessionState;
using System.Security.Principal;
using OWASP.WebGoat.NET.App_Code;
using log4net.Config;
using log4net.Core; // For deprecated hierarchy access
using System.Diagnostics;

// Deprecated: In log4net 1.2.10, this assembly attribute was the recommended way to
// auto-configure log4net at startup.  In log4net 2.0.0+ the attribute no longer
// triggers automatic configuration; callers must explicitly call
// XmlConfigurator.Configure(LogManager.GetRepository(Assembly.GetEntryAssembly()), ...).
[assembly: log4net.Config.XmlConfigurator(ConfigFile = "Web.config", Watch = true)]

namespace OWASP.WebGoat.NET
{
    public class Global : System.Web.HttpApplication
    {

        protected void Application_Start(object sender, EventArgs e)
        {
            // Deprecated: DOMConfigurator is completely deprecated in log4net 2.x
            if (System.Configuration.ConfigurationManager.AppSettings["UseDOMConfig"] == "true")
            {
                DOMConfigurator.Configure(); // Deprecated method
                DOMConfigurator.ConfigureAndWatch(new System.IO.FileInfo("log4net.xml")); // Also deprecated
            }
            
            if (Debugger.IsAttached)
                BasicConfigurator.Configure(); // Deprecated without repository parameter
            else
                XmlConfigurator.Configure(); // Deprecated without repository parameter
            
            Settings.Init(Server);
        }

        protected void Session_Start(object sender, EventArgs e)
        {
        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {

        }

        void Application_PreSendRequestHeaders(Object sender, EventArgs e)
        {
            Response.AddHeader("X-XSS-Protection", "0");
        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {
            //get the role data out of the encrypted cookie and add to current context
            //TODO: get this out of a different cookie

            if (HttpContext.Current.User != null)
            {
                if (HttpContext.Current.User.Identity.IsAuthenticated)
                {
                    if (HttpContext.Current.User.Identity is FormsIdentity)
                    {
                        FormsIdentity id =
                            (FormsIdentity)HttpContext.Current.User.Identity;
                        FormsAuthenticationTicket ticket = id.Ticket;

                        // Get the stored user-data, in this case, our roles
                        string userData = ticket.UserData;
                        string[] roles = userData.Split(',');
                        HttpContext.Current.User = new GenericPrincipal(id, roles);
                    }
                }
            }
        }

        protected void Application_Error(object sender, EventArgs e)
        {

        }

        protected void Session_End(object sender, EventArgs e)
        {

        }

        protected void Application_End(object sender, EventArgs e)
        {

        }
    }
}
