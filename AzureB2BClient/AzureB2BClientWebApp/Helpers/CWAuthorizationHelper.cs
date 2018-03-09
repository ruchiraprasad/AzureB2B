using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AzureB2BClientWebApp.Helpers
{
    public class CWAuthorizationHelper
    {
        public static System.Security.Claims.ClaimsIdentity GetUserIdentty()
        {
            HttpCookie authCookie = HttpContext.Current.Request.Cookies.Get("CWAuthToken");
            if (authCookie != null)
            {
                var secureDataFormat = new TicketDataFormat(new MachineKeyProtector());
                AuthenticationTicket ticket = secureDataFormat.Unprotect(authCookie.Value);
                var identity = ticket != null ? ticket.Identity : null;
                return identity;
            }

            return null;
        }
    }
}