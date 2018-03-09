using AzureB2BClientWebApp.Filters;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace AzureB2BClientWebApp.Controllers
{
    [CWAuthorizationFilter]
    public class AdminController : Controller
    {
        public ActionResult Index()
        {
            var user = HttpContext.User;
            var identity = Helpers.CWAuthorizationHelper.GetUserIdentty();
            return View(identity);
        }

        public ActionResult SignOut()
        {
            FormsAuthentication.SignOut();
            return Redirect(ConfigurationManager.AppSettings["AuthorizationServerUri"] + ConfigurationManager.AppSettings["LogoutPath"] + "?ReturnUrl=" + ConfigurationManager.AppSettings["ClientRedirectUrl"]);
        }
    }
}