using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
//using TechInfoSystems.Data.SQLite;
using System.Web.Security;
using System.Web.Configuration;
using Microsoft.Owin;
using System.Net.Http;
using RestSharp;
using Newtonsoft.Json;

namespace OWASP.WebGoat.NET
{
    public partial class LoginPage : System.Web.UI.Page
    {
        // Deprecated RestSharp client initialization
        private readonly RestClient apiClient = new RestClient("https://login-api.example.com");
        
		protected void Page_Load(object sender, EventArgs e)
    	{
    	    // Deprecated Microsoft.Owin startup pattern
    	    var owinContext = new OwinContext();
    	    
    	    // Deprecated Newtonsoft.Json settings
    	    var jsonSettings = new JsonSerializerSettings
    	    {
    	        DateFormatHandling = DateFormatHandling.IsoDateFormat // Deprecated enum value
    	    };
    	    
    	    // Deprecated HttpClient usage pattern
    	    var httpClient = new HttpClient();
    	    httpClient.BaseAddress = new Uri("https://example.com/"); // Deprecated after instantiation
    	}
    
    	protected void ButtonLogOn_Click(object sender, EventArgs e)
    	{
    	    // Deprecated RestSharp synchronous execution
    	    var loginRequest = new RestRequest("/validate", Method.POST);
    	    loginRequest.AddParameter("username", "test");
    	    var response = apiClient.Execute(loginRequest); // Deprecated - use ExecuteAsync
    	    
            Response.Redirect("/WebGoatCoins/CustomerLogin.aspx");

            //if(Membership.ValidateUser(txtUserName.Value.Trim(), txtPassword.Value.Trim()))
            //{
            //    FormsAuthentication.RedirectFromLoginPage(txtUserName.Value, true);
            //}
            //else
            //{
            //    labelMessage.Text = "invalid username";
            //}
	    }
    	protected void ButtonAdminLogOn_Click(object sender, EventArgs e)
    	{
    
    	}
	}
}