using System;
using System.IO;
using System.Reflection;
using log4net;
using log4net.Appender;
using log4net.Config;
using log4net.Core;
using log4net.Layout;
using log4net.Repository.Hierarchy;

namespace OWASP.WebGoat.NET.App_Code
{
    /// <summary>
    /// Demonstrates log4net 1.2.10 APIs that are breaking changes when upgrading to 2.0.0+.
    ///
    /// Breaking changes summary:
    ///   1. log4net.NDC  — class entirely REMOVED in 2.0 (compile error on upgrade)
    ///   2. log4net.MDC  — class entirely REMOVED in 2.0 (compile error on upgrade)
    ///   3. DOMConfigurator — class REMOVED in 2.0
    ///   4. XmlConfigurator.Configure() / BasicConfigurator.Configure() without an
    ///      ILoggerRepository argument — deprecated; in 2.x the no-arg overloads no
    ///      longer exist and a repository must be passed explicitly.
    ///   5. [assembly: XmlConfigurator] attribute — no longer triggers auto-config in 2.x
    ///   6. LogManager.GetRepository() without an assembly argument — signature changed
    ///   7. PatternLayout %ndc / %mdc conversion characters — removed in 2.x
    ///      (use %property{key} instead)
    ///   8. FileAppender.ExclusiveLock / MinimalLock — locking-model API restructured
    ///   9. RollingFileAppender.ImmediateFlush property — removed in 2.0
    ///  10. Hierarchy.Root.AddAppender() without calling
    ///      LogManager.GetRepository(Assembly) first
    /// </summary>
    public static class Log4NetLegacyHelper
    {
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// Sets up a RollingFileAppender using APIs that break on upgrade to log4net 2.0+.
        /// </summary>
        public static void ConfigureLegacyRollingAppender(string logFilePath)
        {
            // Breaking change #7: PatternLayout using %ndc and %mdc conversion characters.
            // These were removed in log4net 2.0.  The replacements are %property{key}
            // for MDC entries and %ndc is simply gone (ThreadContext stack renders via %property).
            var legacyPattern = new PatternLayout
            {
                ConversionPattern = "%date [%thread] %ndc %mdc{page} %-5level %logger - %message%newline"
            };
            legacyPattern.ActivateOptions();

            var rollingAppender = new RollingFileAppender
            {
                Layout = legacyPattern,
                File = logFilePath,
                AppendToFile = true,
                RollingStyle = RollingFileAppender.RollingMode.Size,
                MaxSizeRollBackups = 5,
                MaximumFileSize = "10MB",

                // Breaking change #9: ImmediateFlush was removed in log4net 2.0.
                // In 2.x the property does not exist on RollingFileAppender.
                ImmediateFlush = true,

                // Breaking change #8: Setting LockingModel via the concrete ExclusiveLock type.
                // In log4net 2.0 the locking model API was restructured; ExclusiveLock still
                // exists but the recommended approach and internal contracts changed, and code
                // that casts to FileAppender.ExclusiveLock directly will fail if the internal
                // type was refactored.
                LockingModel = new FileAppender.ExclusiveLock()
            };
            rollingAppender.ActivateOptions();

            // Breaking change #6 + #10: LogManager.GetRepository() called without an assembly.
            // In log4net 2.0 the no-argument overload was removed; callers must pass an Assembly.
            var hierarchy = (Hierarchy)LogManager.GetRepository();
            hierarchy.Root.AddAppender(rollingAppender);
            hierarchy.Configured = true;
        }

        /// <summary>
        /// Demonstrates the legacy NDC (Nested Diagnostic Context) API.
        /// log4net.NDC was completely REMOVED in log4net 2.0 — this code will not
        /// compile if the package is upgraded.
        /// </summary>
        public static void UseNdcLegacyApi(string operationName)
        {
            // Breaking change #1: log4net.NDC class removed in 2.0
            log4net.NDC.Push(operationName);          // NDC.Push — does not exist in 2.x
            log4net.NDC.Set("override-context");      // NDC.Set  — does not exist in 2.x

            log.Info("Performing operation inside NDC context: " + operationName);

            string currentContext = log4net.NDC.Get(); // NDC.Get  — does not exist in 2.x
            log.Debug("Current NDC context value: " + currentContext);

            int depth = log4net.NDC.Depth;            // NDC.Depth — does not exist in 2.x
            log.Debug("NDC stack depth: " + depth);

            log4net.NDC.Pop();                        // NDC.Pop  — does not exist in 2.x
            log4net.NDC.Clear();                      // NDC.Clear — does not exist in 2.x
        }

        /// <summary>
        /// Demonstrates the legacy MDC (Mapped Diagnostic Context) API.
        /// log4net.MDC was completely REMOVED in log4net 2.0 — this code will not
        /// compile if the package is upgraded.
        /// </summary>
        public static void UseMdcLegacyApi(string userId, string requestId)
        {
            // Breaking change #2: log4net.MDC class removed in 2.0
            log4net.MDC.Set("userId",    userId);     // MDC.Set    — does not exist in 2.x
            log4net.MDC.Set("requestId", requestId);  // MDC.Set    — does not exist in 2.x

            string resolvedUser = log4net.MDC.Get("userId"); // MDC.Get — does not exist in 2.x
            log.Info("Processing request for MDC user: " + resolvedUser);

            log4net.MDC.Remove("requestId");          // MDC.Remove — does not exist in 2.x
        }

        /// <summary>
        /// Uses the deprecated no-argument Configure() overloads that were removed in 2.0+.
        /// </summary>
        public static void ConfigureWithDeprecatedOverloads()
        {
            // Breaking change #3: DOMConfigurator removed in 2.0
            DOMConfigurator.Configure();

            // Breaking change #4: no-argument overloads removed in 2.0 — must pass ILoggerRepository
            BasicConfigurator.Configure();
            XmlConfigurator.Configure();
            XmlConfigurator.ConfigureAndWatch(new FileInfo("log4net.config"));
        }

        /// <summary>
        /// Accesses the repository hierarchy using the legacy no-argument GetRepository() overload.
        /// </summary>
        public static Level GetRootLevel()
        {
            // Breaking change #6: GetRepository() without an assembly argument removed in 2.0
            var hierarchy = (Hierarchy)LogManager.GetRepository();
            return hierarchy.Root.Level;
        }
    }
}
