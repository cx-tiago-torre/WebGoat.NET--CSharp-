using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Threading.Tasks;
using OWASP.WebGoat.NET.App_Code;
using OWASP.WebGoat.NET.Content;

namespace OWASP.WebGoat.NET
{
    public partial class CSRFDemo : System.Web.UI.Page
    {
        protected async void Page_Load(object sender, EventArgs e)
        {
            if (Request.Form["apiData"] != null)
            {
                await ProcessApiDataWithDeprecatedMethods(Request.Form["apiData"]);
            }
        }

        private async Task ProcessApiDataWithDeprecatedMethods(string apiData)
        {
            try
            {
                // Using deprecated JSON deserialization
                var data = DeprecatedMethodsUtility.DeserializeJsonUnsafe(apiData);
                
                // Using deprecated HTTP service
                var httpResult = await DeprecatedHttpService.MakeDeprecatedHttpRequest(
                    "https://api.webgoat.local/process", 
                    data
                );

                // Using deprecated OData processing
                var oDataResult = DeprecatedHttpService.CreateDeprecatedODataResponse(
                    new[] { data, new { timestamp = DateTime.Now, source = "csrf-demo" } }
                );

                // Using deprecated YAML processing
                var yamlConfig = "settings:\n  enabled: true\n  timeout: 30";
                var configData = DeprecatedMethodsUtility.DeserializeYamlDeprecated<Dictionary<string, object>>(yamlConfig);

                // Using deprecated JWT processing
                var jwtToken = DeprecatedMethodsUtility.CreateJwtTokenDeprecated(
                    new Dictionary<string, object> { { "user", "csrf-user" }, { "role", "demo" } }
                );

                // Chain all deprecated method calls together
                var finalResult = DeprecatedMethodsUtility.ProcessComplexDataDeprecated(
                    DeprecatedMethodsUtility.SerializeWithDeprecatedSettings(new
                    {
                        httpResult,
                        oDataResult,
                        configData,
                        jwtToken
                    }),
                    jwtToken
                );

                // Log using deprecated logging
                Util.LogWithDeprecatedMethods($"CSRF Demo processed with deprecated methods: {finalResult}");

                Response.Write($"CSRF Demo Result: {finalResult}");
            }
            catch (Exception ex)
            {
                Util.LogWithDeprecatedMethods("CSRF Demo failed with deprecated processing", ex);
                Response.Write($"CSRF Demo Error: {ex.Message}");
            }
        }
    }
}