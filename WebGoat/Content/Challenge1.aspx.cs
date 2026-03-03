using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using RestSharp;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET
{
    public partial class Challenge1 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request.QueryString["data"] != null)
            {
                ProcessUserData(Request.QueryString["data"]);
            }
        }

        private void ProcessUserData(string userData)
        {
            try
            {
                // Using deprecated Newtonsoft.Json deserialization
                var settings = new JsonSerializerSettings
                {
                    // TypeNameHandling.All is deprecated and vulnerable
                    TypeNameHandling = TypeNameHandling.All,
                    DateFormatHandling = DateFormatHandling.MicrosoftDateFormat // Deprecated format
                };
                
                var deserializedData = JsonConvert.DeserializeObject(userData, settings);
                                // Call our deprecated utility methods
                DeprecatedMethodsUtility.LogWithDeprecatedMethods(\"Processing Challenge1 user data\");
                
                // Use more deprecated methods from the utility class
                var processedData = DeprecatedMethodsUtility.SerializeWithDeprecatedSettings(deserializedData);
                var restResult = DeprecatedMethodsUtility.MakeRestCallDeprecated(\"/challenge1\", deserializedData);
                var systemTextJsonResult = DeprecatedMethodsUtility.SerializeSystemTextJsonDeprecated(deserializedData);
                                // Using deprecated RestSharp methods
                var client = new RestClient("https://api.example.com");
                var request = new RestRequest();
                request.Method = Method.POST; // Enum usage deprecated
                request.AddJsonBody(deserializedData); // Method deprecated
                
                var response = client.Execute(request); // Method signature deprecated
                
                // Process response using deprecated utility
                var result = DeprecatedMethodsUtility.SerializeWithDeprecatedSettings(response.Content);
                
                Response.Write($"Processed: {result}");
            }
            catch (Exception ex)
            {
                Response.Write($"Error: {ex.Message}");
            }
        }
    }
}