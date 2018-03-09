using AzureB2BClientWebApp.Helpers;
using DotNetOpenAuth.OAuth2;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace AzureB2BClientWebApp.Controllers
{
    public class AccountController : Controller
    {
        private WebServerClient _webServerClient;

        public ActionResult Index()
        {
            var accessToken = Request.Form["AccessToken"] ?? "";
            var refreshToken = Request.Form["RefreshToken"] ?? "";
            InitializeWebServerClient();

            if (string.IsNullOrEmpty(accessToken))
            {
                var authorizationState = _webServerClient.ProcessUserAuthorization(Request);
                if (authorizationState != null)
                {
                    var secureDataFormat = new TicketDataFormat(new MachineKeyProtector());
                    AuthenticationTicket ticket = secureDataFormat.Unprotect(authorizationState.AccessToken);
                    var identity = ticket != null ? ticket.Identity : null;

                    // Add the cookie to the request to save it
                    HttpCookie cookie = new HttpCookie("CWAuthToken", authorizationState.AccessToken);
                    cookie.HttpOnly = true;
                    HttpContext.Response.Cookies.Add(cookie);
                    Response.Cookies.Add(cookie);

                    FormsAuthentication.SetAuthCookie(identity.Name, false);

                    return RedirectToAction("index", "admin");
                }

                Response.Cookies["CWAuthToken"].Expires = DateTime.Now.AddDays(-1);

                return RedirectToAction("Index", "Home");
            }

            return View();
        }

        private void InitializeWebServerClient()
        {
            var authorizationServerUri = new Uri(ConfigurationManager.AppSettings["AuthorizationServerUri"]);
            var authorizationServer = new AuthorizationServerDescription
            {
                AuthorizationEndpoint = new Uri(authorizationServerUri, ConfigurationManager.AppSettings["AuthorizePath"]),
                TokenEndpoint = new Uri(authorizationServerUri, ConfigurationManager.AppSettings["TokenPath"])
            };

            _webServerClient = new WebServerClient(authorizationServer, ConfigurationManager.AppSettings["ClientId"], ConfigurationManager.AppSettings["ClientSecret"]);
        }
    }
}