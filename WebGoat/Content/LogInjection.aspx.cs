using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Reflection;
using log4net;
using log4net.Config;

// Deprecated: assembly-level XmlConfigurator attribute is the 1.x config approach.
// In log4net 2.0+, this attribute no longer auto-configures the repository and
// must be replaced with an explicit XmlConfigurator.Configure(ILoggerRepository, FileInfo) call.
[assembly: log4net.Config.XmlConfigurator(ConfigFile = "log4net.config", Watch = true)]

namespace OWASP.WebGoat.NET
{
    public partial class LogInjection : System.Web.UI.Page
    {
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        protected void Page_Load(object sender, EventArgs e)
        {
            // Deprecated: log4net.NDC (Nested Diagnostic Context) class was completely
            // REMOVED in log4net 2.0.0. Code using it will not compile against 2.x.
            // The replacement is log4net.ThreadContext.Stacks["NDC"].Push(...)
            log4net.NDC.Push("Page_Load");
            log4net.NDC.Set("LogInjectionPage");

            // Deprecated: log4net.MDC (Mapped Diagnostic Context) class was completely
            // REMOVED in log4net 2.0.0. Code using it will not compile against 2.x.
            // The replacement is log4net.ThreadContext.Properties["key"] = value
            log4net.MDC.Set("page", "LogInjection");
            log4net.MDC.Set("sessionId", Session.SessionID);

            log.Info("LogInjection page loaded");

            // Retrieve from MDC using the 1.x API (removed in 2.0)
            string pageContext = log4net.MDC.Get("page");
            log.Debug("Context from MDC: " + pageContext);

            log4net.NDC.Pop();
        }

        protected void Page_PreRender(object sender, EventArgs e)
        {
            string userInput = Request.QueryString["input"];
            if (!string.IsNullOrEmpty(userInput))
            {
                // Deprecated: MDC.Set / MDC.Get pattern — removed in log4net 2.0
                log4net.MDC.Set("userInput", userInput);
                log4net.NDC.Push("Page_PreRender");

                // Log user-controlled input directly (also demonstrates log injection)
                log.Warn("User submitted: " + userInput);

                log4net.NDC.Pop();
                log4net.MDC.Remove("userInput");
            }
        }
    }
}