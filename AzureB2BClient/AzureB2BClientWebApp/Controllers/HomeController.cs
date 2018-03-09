using DotNetOpenAuth.OAuth2;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Web;
using System.Web.Mvc;

namespace AzureB2BClientWebApp.Controllers
{
    public class HomeController : Controller
    {
        private WebServerClient _webServerClient;

        public ActionResult Index()
        {
            ViewBag.AccessToken = Request.Form["AccessToken"] ?? "";
            ViewBag.RefreshToken = Request.Form["RefreshToken"] ?? "";
            ViewBag.Action = "";
            ViewBag.ApiResponse = "";

            InitializeWebServerClient();
            var accessToken = Request.Form["AccessToken"];

            if (!string.IsNullOrEmpty(Request.Form.Get("submit.Authorize")))
            {
                var userAuthorization = _webServerClient.PrepareRequestUserAuthorization(new[] { "Email", "Name" }, new Uri(ConfigurationManager.AppSettings["ClientRedirectUrl"]));
                userAuthorization.Send(HttpContext);
                Response.End();
            }
            else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Refresh")))
            {
                var state = new AuthorizationState
                {
                    AccessToken = Request.Form["AccessToken"],
                    RefreshToken = Request.Form["RefreshToken"]
                };

                if (_webServerClient.RefreshAuthorization(state))
                {
                    ViewBag.AccessToken = state.AccessToken;
                    ViewBag.RefreshToken = state.RefreshToken;
                }
            }
            else if (!string.IsNullOrEmpty(Request.Form.Get("submit.CallApi")))
            {
                var resourceServerUri = new Uri(ConfigurationManager.AppSettings["ResourceServerBaseAddress"]);
                var client = new HttpClient(_webServerClient.CreateAuthorizingHandler(accessToken));
                var body = client.GetStringAsync(new Uri(resourceServerUri, ConfigurationManager.AppSettings["MePath"])).Result;
                ViewBag.ApiResponse = body;
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

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}