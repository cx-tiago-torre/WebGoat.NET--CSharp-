using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens;
using RestSharp;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using log4net;
using log4net.Config;
using log4net.Core; // For deprecated hierarchy access
using System.Net.Http;
using Microsoft.Owin;
using System.Text.Json;
using Microsoft.Data.OData;
using System.Reflection;

namespace OWASP.WebGoat.NET.App_Code
{
    /// <summary>
    /// Utility class demonstrating deprecated methods from vulnerable packages
    /// </summary>
    public class DeprecatedMethodsUtility
    {
        // Using deprecated Newtonsoft.Json methods
        public static object DeserializeJsonUnsafe(string jsonData)
        {
            // JsonConvert.DeserializeObject without type checking was deprecated in later versions
            return JsonConvert.DeserializeObject(jsonData, new JsonSerializerSettings
            {
                // TypeNameHandling.All is deprecated and unsafe
                TypeNameHandling = TypeNameHandling.All,
                // DateFormatHandling is deprecated in newer versions
                DateFormatHandling = DateFormatHandling.MicrosoftDateFormat
            });
        }

        public static string SerializeWithDeprecatedSettings(object obj)
        {
            return JsonConvert.SerializeObject(obj, new JsonSerializerSettings
            {
                // These converters and settings have deprecated constructors/usage
                Converters = { new IsoDateTimeConverter() },
                DateFormatHandling = DateFormatHandling.MicrosoftDateFormat,
                // NullValueHandling enum values changed in later versions
                NullValueHandling = NullValueHandling.Include
            });
        }

        // Using deprecated JWT methods
        public static string CreateJwtTokenDeprecated(Dictionary<string, object> payload)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // JwtSecurityToken constructor overload deprecated in newer versions
            var token = new JwtSecurityToken(
                issuer: "webgoat",
                audience: "users",
                claims: null, // This parameter usage was deprecated
                expires: DateTime.UtcNow.AddHours(1),
                // SigningCredentials constructor is deprecated
                signingCredentials: new SigningCredentials(
                    new InMemorySymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("deprecated-key")),
                    SecurityAlgorithms.HmacSha256Signature // This constant was deprecated
                )
            );

            return tokenHandler.WriteToken(token);
        }

        // Using deprecated RestSharp methods
        public static string MakeDeprecatedRestCall(string url, object data)
        {
            // RestClient constructor and methods changed significantly in newer versions
            var client = new RestClient(url);
            var request = new RestRequest();
            
            // Method.POST enum value and AddJsonBody were deprecated
            request.Method = Method.POST;
            request.AddJsonBody(data); // Deprecated in favor of AddBody
            
            // Execute method signature changed in newer versions
            var response = client.Execute(request);
            return response.Content;
        }

        // Using deprecated YamlDotNet methods
        public static T DeserializeYamlDeprecated<T>(string yamlContent)
        {
            // DeserializerBuilder API changed significantly in newer versions
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(new CamelCaseNamingConvention()) // Constructor deprecated
                .Build();

            return deserializer.Deserialize<T>(yamlContent);
        }

        public static string SerializeYamlDeprecated(object obj)
        {
            // SerializerBuilder API changed significantly in newer versions  
            var serializer = new SerializerBuilder()
                .WithNamingConvention(new CamelCaseNamingConvention()) // Constructor deprecated
                .Build();

            return serializer.Serialize(obj);
        }

        // Method using multiple deprecated features together
        public static string ProcessComplexDataDeprecated(string jsonInput, string jwtToken)
        {
            try
            {
                // Chain deprecated method calls
                var data = DeserializeJsonUnsafe(jsonInput);
                var processedData = SerializeWithDeprecatedSettings(data);
                
                // Use deprecated JWT validation
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParams = new TokenValidationParameters
                {
                    // IssuerSigningKey property usage deprecated in newer versions
                    IssuerSigningKey = new InMemorySymmetricSecurityKey(
                        System.Text.Encoding.UTF8.GetBytes("deprecated-key")
                    ),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // ValidateLifetime usage changed in newer versions
                    ValidateLifetime = false
                };

                SecurityToken validatedToken;
                // ValidateToken method signature changed in newer versions
                var principal = tokenHandler.ValidateToken(jwtToken, validationParams, out validatedToken);

                return processedData;
            }
            catch (Exception ex)
            {
                // Even exception handling patterns changed in some packages
                LogWithDeprecatedMethods("Error processing data: " + ex.Message);
                return JsonConvert.SerializeObject(new { error = ex.Message });
            }
        }
        
        /// <summary>
        /// Demonstrates deprecated log4net methods from version 1.2.10
        /// TODO: Updated for log4net 2.x compatibility - DOMConfigurator removed, configurators now require repository parameter
        /// </summary>
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        
        public static void LogWithDeprecatedMethods(string message)
        {
            // log4net 2.x update: DOMConfigurator is completely removed, use XmlConfigurator instead
            var repository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            XmlConfigurator.Configure(repository);
            XmlConfigurator.ConfigureAndWatch(repository, new System.IO.FileInfo("log4net.config"));
            
            // log4net 2.x update: XmlConfigurator now requires repository parameter
            XmlConfigurator.Configure(repository);
            XmlConfigurator.ConfigureAndWatch(repository, new System.IO.FileInfo("log4net.config"));
            
            // log4net 2.x update: BasicConfigurator now requires repository parameter
            BasicConfigurator.Configure(repository);
            
            // ThreadContext usage - still available in log4net 2.x
            log4net.ThreadContext.Properties["method"] = "LogWithDeprecatedMethods";
            log4net.ThreadContext.Stacks["callstack"].Push(message);
            
            // log4net 2.x update: Hierarchy manipulation with repository context
            var hierarchy = (log4net.Repository.Hierarchy.Hierarchy)repository;
            hierarchy.Root.Level = Level.Debug;
            hierarchy.Configured = true;
            
            // Logger.GetLogger with string parameter still supported
            var stringLogger = LogManager.GetLogger("DeprecatedLogger");
            
            stringLogger.Info("Deprecated logger: " + message);
            log.Debug("Using deprecated logger pattern");
        }
        
        /// <summary>
        /// Demonstrates deprecated RestSharp methods
        /// </summary>
        public static string MakeRestCallDeprecated(string endpoint, object data)
        {
            // Deprecated RestSharp client construction
            var client = new RestClient("https://api.example.com");
            
            // Deprecated Method enum and request construction
            var request = new RestRequest(endpoint, Method.POST);
            request.AddObject(data); // AddObject is deprecated
            
            // Deprecated synchronous execution
            var response = client.Execute(request); // Should use ExecuteAsync
            return response.Content;
        }
        
        /// <summary>
        /// Demonstrates deprecated HttpClient patterns
        /// </summary>
        public static string MakeHttpCallDeprecated(string url)
        {
            // Deprecated HttpClient constructor pattern
            using (var handler = new HttpClientHandler())
            using (var client = new HttpClient(handler))
            {
                // Setting BaseAddress after construction is deprecated
                client.BaseAddress = new Uri(url);
                
                // Synchronous call pattern is deprecated
                var response = client.GetAsync("/api/test").Result;
                return response.Content.ReadAsStringAsync().Result;
            }
        }
        
        /// <summary>
        /// Demonstrates deprecated System.Text.Json patterns
        /// </summary>
        public static string SerializeSystemTextJsonDeprecated(object obj)
        {
            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true,
                IgnoreNullValues = true // This property is deprecated
            };
            
            return System.Text.Json.JsonSerializer.Serialize(obj, options);
        }
        
        /// <summary>
        /// Demonstrates deprecated OData patterns
        /// </summary>
        public static void WorkWithDeprecatedOData()
        {
            var serviceUri = new Uri("http://services.odata.org/V3/Northwind/Northwind.svc/");
            
            // Direct URI manipulation - deprecated approach
            var odataUri = new UriBuilder(serviceUri)
            {
                Path = serviceUri.Path + "Products"
            }.Uri;
            
            log.Info($"OData URI: {odataUri}");
        }
        
        /// <summary>
        /// Demonstrates deprecated OWIN patterns
        /// </summary>
        public static void ConfigureOwinDeprecated()
        {
            // Direct OwinContext instantiation is deprecated
            var context = new OwinContext();
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
        }
        }
    }
}