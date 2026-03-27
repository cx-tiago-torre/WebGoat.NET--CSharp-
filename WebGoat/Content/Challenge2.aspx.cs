using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET
{
    public partial class Challenge2 : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request.Form["token"] != null && Request.Form["config"] != null)
            {
                ProcessTokenAndConfig(Request.Form["token"], Request.Form["config"]);
            }
        }

        private void ProcessTokenAndConfig(string token, string yamlConfig)
        {
            try
            {
                // Using deprecated JWT token creation and validation
                var tokenHandler = new JwtSecurityTokenHandler();
                
                // Deprecated JwtSecurityToken constructor
                var newToken = new JwtSecurityToken(
                    issuer: "webgoat-challenge2",
                    audience: "users",
                    claims: null, // Parameter usage deprecated
                    expires: DateTime.UtcNow.AddHours(2),
                    signingCredentials: new SigningCredentials(
                        new InMemorySymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("challenge2-secret")),
                        SecurityAlgorithms.HmacSha256Signature // Constant deprecated
                    )
                );

                // Using deprecated YamlDotNet deserialization
                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(new CamelCaseNamingConvention()) // Constructor deprecated
                    .Build();

                var config = deserializer.Deserialize<Dictionary<string, object>>(yamlConfig);
                
                // Deprecated token validation
                var validationParams = new TokenValidationParameters
                {
                    IssuerSigningKey = new InMemorySymmetricSecurityKey(
                        System.Text.Encoding.UTF8.GetBytes("challenge2-secret")
                    ), // Property usage deprecated
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false // Usage pattern deprecated
                };

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(token, validationParams, out validatedToken); // Method signature deprecated

                // Process using deprecated utility methods
                var result = DeprecatedMethodsUtility.ProcessComplexDataDeprecated(
                    DeprecatedMethodsUtility.SerializeWithDeprecatedSettings(config),
                    tokenHandler.WriteToken(newToken)
                );

                Response.Write($"Challenge2 Result: {result}");
            }
            catch (Exception ex)
            {
                Response.Write($"Challenge2 Error: {ex.Message}");
            }
        }
    }
}