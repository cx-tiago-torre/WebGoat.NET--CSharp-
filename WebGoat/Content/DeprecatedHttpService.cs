using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text;
using Microsoft.Data.OData;
using Microsoft.Data.Edm;
using System.IO;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET.Content
{
    /// <summary>
    /// Service class demonstrating deprecated HTTP and OData methods
    /// </summary>
    public class DeprecatedHttpService
    {
        // Using deprecated HttpClient patterns
        public static async Task<string> MakeDeprecatedHttpRequest(string url, object data)
        {
            // HttpClient usage without proper disposal (pattern deprecated)
            var client = new HttpClient();
            
            // HttpContent creation using deprecated methods
            var json = DeprecatedMethodsUtility.SerializeWithDeprecatedSettings(data);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            
            try
            {
                // These method overloads and usage patterns were deprecated
                var response = await client.PostAsync(url, content);
                
                // ReadAsStringAsync without proper error handling (pattern deprecated)
                var responseContent = await response.Content.ReadAsStringAsync();
                
                return responseContent;
            }
            catch (HttpRequestException ex)
            {
                // Exception handling pattern deprecated
                Util.LogWithDeprecatedMethods("HTTP request failed", ex);
                throw;
            }
            // Note: Not disposing HttpClient properly - deprecated pattern
        }

        // Using deprecated OData methods
        public static string CreateDeprecatedODataResponse(IEnumerable<object> data)
        {
            try
            {
                // ODataMessageWriterSettings constructor usage deprecated
                var settings = new ODataMessageWriterSettings
                {
                    // These property assignments changed in newer versions
                    Indent = true,
                    CheckCharacters = false, // Property deprecated
                    Version = ODataVersion.V3 // V3 support deprecated
                };

                using (var stream = new MemoryStream())
                {
                    // IODataResponseMessage implementation patterns deprecated
                    var message = new InMemoryMessage { Stream = stream };
                    message.SetHeader("Content-Type", "application/json;odata=verbose"); // Verbose format deprecated

                    using (var writer = new ODataMessageWriter(message, settings))
                    {
                        // These writer method signatures changed in newer versions
                        var entitySetWriter = writer.CreateODataFeedWriter();
                        
                        // ODataFeed constructor and property usage deprecated
                        var feed = new ODataFeed
                        {
                            Id = new Uri("http://example.com/feed"), // Property usage deprecated
                            Count = ((System.Collections.ICollection)data).Count // Count property deprecated
                        };

                        entitySetWriter.WriteStart(feed);
                        
                        foreach (var item in data)
                        {
                            // ODataEntry creation pattern deprecated
                            var entry = new ODataEntry
                            {
                                Id = new Uri($"http://example.com/item/{item.GetHashCode()}"), // Property usage deprecated
                                Properties = ConvertToODataProperties(item) // Method pattern deprecated
                            };
                            
                            entitySetWriter.WriteStart(entry);
                            entitySetWriter.WriteEnd();
                        }
                        
                        entitySetWriter.WriteEnd();
                        entitySetWriter.Flush(); // Method deprecated in newer versions
                    }

                    return Encoding.UTF8.GetString(stream.ToArray());
                }
            }
            catch (Exception ex)
            {
                Util.LogWithDeprecatedMethods("OData processing failed", ex);
                return DeprecatedMethodsUtility.SerializeWithDeprecatedSettings(new { error = ex.Message });
            }
        }

        // Helper method using deprecated OData property conversion
        private static IEnumerable<ODataProperty> ConvertToODataProperties(object item)
        {
            var properties = new List<ODataProperty>();
            
            foreach (var prop in item.GetType().GetProperties())
            {
                // ODataProperty constructor usage deprecated
                var odataProperty = new ODataProperty
                {
                    Name = prop.Name,
                    Value = prop.GetValue(item, null) // GetValue overload usage deprecated
                };
                
                properties.Add(odataProperty);
            }
            
            return properties;
        }

        // Inner class for deprecated message pattern
        private class InMemoryMessage : IODataResponseMessage
        {
            public Stream Stream { get; set; }
            private readonly Dictionary<string, string> _headers = new Dictionary<string, string>();

            // These interface implementations changed significantly in newer versions
            public IEnumerable<KeyValuePair<string, string>> Headers => _headers;

            public int StatusCode { get; set; } // Property implementation pattern deprecated

            public Stream GetStream()
            {
                return Stream; // Direct return pattern deprecated
            }

            public string GetHeader(string headerName)
            {
                return _headers.ContainsKey(headerName) ? _headers[headerName] : null; // Pattern deprecated
            }

            public void SetHeader(string headerName, string headerValue)
            {
                _headers[headerName] = headerValue; // Direct assignment deprecated
            }
        }
    }
}