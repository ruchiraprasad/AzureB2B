using AzureB2BClientWebApp.Helpers;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace AzureB2BClientWebApp.Filters
{
    public class CWAuthorizationFilter : ActionFilterAttribute, IActionFilter
    {
        void IActionFilter.OnActionExecuting(ActionExecutingContext filterContext)
        {
            HttpCookie authCookie = HttpContext.Current.Request.Cookies.Get("CWAuthToken");
            var isAuthenticated = false;
            if (authCookie != null)
            {
                var secureDataFormat = new TicketDataFormat(new MachineKeyProtector());
                AuthenticationTicket ticket = secureDataFormat.Unprotect(authCookie.Value);
                var identity = ticket != null ? ticket.Identity : null;

                if (identity != null && identity.IsAuthenticated)
                {
                    isAuthenticated = true;

                    List<string> roles = new List<string>();
                    foreach (var item in identity.Claims.Where(s => s.ToString().Contains("cw:oauth:")))
                    {
                        var tempStr = item.ToString().Substring("cw:oauth:".Length);
                        roles.Add(tempStr.Substring(0, tempStr.IndexOf(":")));
                    }

                }
            }

            if (!isAuthenticated)
            {
                filterContext.Result = new RedirectToRouteResult(
                    new RouteValueDictionary(
                        new
                        {
                            controller = "Home",
                            action = "Index"
                        })
                    );
            }
        }
    }
}