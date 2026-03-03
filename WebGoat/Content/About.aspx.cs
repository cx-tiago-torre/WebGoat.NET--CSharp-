using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using YamlDotNet.Serialization;
using Microsoft.Data.OData;
using System.IdentityModel.Tokens.Jwt;
using log4net;
using System.Reflection;

namespace OWASP.WebGoat.NET
{
    public partial class About : System.Web.UI.Page
    {
        // Deprecated log4net logger initialization
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        
        protected void Page_Load(object sender, EventArgs e)
        {
            // Deprecated YamlDotNet Serializer constructor
            var yamlSerializer = new Serializer(); // Deprecated parameterless constructor
            var data = new { Name = "Test", Value = 123 };
            var yaml = yamlSerializer.Serialize(data);
            
            // Deprecated JWT token handler
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor(); // Deprecated approach
            
            // Deprecated OData URI parser
            var odataUri = new System.Uri("http://services.odata.org/");
            
            log.Warn("Using deprecated methods in About page");
        }
    }
}