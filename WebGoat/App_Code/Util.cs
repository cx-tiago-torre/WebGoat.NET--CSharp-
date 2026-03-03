using System;
using System.Diagnostics;
using log4net;
using log4net.Config;
using log4net.Appender;
using log4net.Layout;
using log4net.Core; // For deprecated hierarchy access
using System.Reflection;
using System.IO;
using System.Threading;

namespace OWASP.WebGoat.NET.App_Code
{
    public class Util
    {
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        
        // Deprecated log4net configuration method
        static Util()
        {
            // Deprecated: XmlConfigurator.Configure() without parameters is deprecated in 2.x
            XmlConfigurator.Configure();
            
            // Deprecated: DOMConfigurator usage
            if (System.IO.File.Exists("log4net.xml"))
            {
                DOMConfigurator.Configure(new System.IO.FileInfo("log4net.xml")); // Deprecated class
            }
            
            // Deprecated: Direct ThreadContext manipulation
            log4net.ThreadContext.Properties["component"] = "Util";
            log4net.ThreadContext.Stacks["operation"].Push("static-constructor");
        }
        
        // Deprecated logging setup with old patterns
        public static void SetupDeprecatedLogging()
        {
            // XmlConfigurator.Configure() without parameters is deprecated
            XmlConfigurator.Configure();
            
            // Creating appenders programmatically using deprecated constructors
            var fileAppender = new FileAppender
            {
                Layout = new PatternLayout("%date [%thread] %-5level %logger - %message%newline"), // Constructor deprecated
                File = "deprecated-log.txt",
                AppendToFile = true
            };
            
            // Deprecated FileAppender.ActivateOptions() method
            fileAppender.ActivateOptions(); // Deprecated in newer versions
            
            // Deprecated Logger.GetLogger with string parameter
            var stringLogger = LogManager.GetLogger("DeprecatedLogger"); // Deprecated approach
            
            // ActivateOptions() method deprecated in newer versions
            fileAppender.ActivateOptions();
            
            // Adding appender using deprecated method
            ((log4net.Repository.Hierarchy.Hierarchy)LogManager.GetRepository()).Root.AddAppender(fileAppender);
        }

        // Method using deprecated logging patterns
        public static void LogWithDeprecatedMethods(string message, Exception ex = null)
        {
            // Deprecated: ThreadContext is deprecated in favor of LogicalThreadContext
            log4net.ThreadContext.Properties["user"] = "deprecated-user";
            log4net.ThreadContext.Stacks["operation"].Push("deprecated-operation");
            
            // Deprecated: Direct hierarchy access without repository context
            var hierarchy = (log4net.Repository.Hierarchy.Hierarchy)LogManager.GetRepository();
            var rootLogger = hierarchy.Root;
            rootLogger.Level = log4net.Core.Level.Debug; // Deprecated direct manipulation
            
            // These logging method overloads were deprecated in newer versions
            if (ex != null)
            {
                log.Error(message, ex); // This overload pattern changed
            }
            else
            {
                log.Info(message); // Simple overload deprecated in favor of structured logging
            }
            
            // GlobalContext usage deprecated in newer versions
            log4net.GlobalContext.Properties["deprecated-property"] = "deprecated-value";
        }
        
        public static int RunProcessWithInput(string cmd, string args, string input)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                WorkingDirectory = Settings.RootDir,
                FileName = cmd,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };

            using (Process process = new Process())
            {
                process.EnableRaisingEvents = true;
                process.StartInfo = startInfo;

                process.OutputDataReceived += (sender, e) => {
                    if (e.Data != null)
                        log.Info(e.Data);
                };

                process.ErrorDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                        log.Error(e.Data);
                };

                AutoResetEvent are = new AutoResetEvent(false);

                process.Exited += (sender, e) => 
                {
                    Thread.Sleep(1000);
                    are.Set();
                    log.Info("Process exited");

                };

                process.Start();

                using (StreamReader reader = new StreamReader(new FileStream(input, FileMode.Open)))
                {
                    string line;
                    string replaced;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                            replaced = line.Replace("DB_Scripts/datafiles/", "DB_Scripts\\\\datafiles\\\\");
                        else
                            replaced = line;

                        log.Debug("Line: " + replaced);
                        
                        // Using our deprecated logging method
                        LogWithDeprecatedMethods("Processing line with deprecated logging: " + replaced);

                        process.StandardInput.WriteLine(replaced);
                    }
                }
    
                process.StandardInput.Close();
    

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
    
                //NOTE: Looks like we have a mono bug: https://bugzilla.xamarin.com/show_bug.cgi?id=6291
                //have a wait time for now.
                
                are.WaitOne(10 * 1000);

                if (process.HasExited)
                    return process.ExitCode;
                else //WTF? Should have exited dammit!
                {
                    process.Kill();
                    return 1;
                }
            }
        }
    }
}

