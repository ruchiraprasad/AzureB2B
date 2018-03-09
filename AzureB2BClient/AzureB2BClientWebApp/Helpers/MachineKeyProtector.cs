using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AzureB2BClientWebApp.Helpers
{
    public class MachineKeyProtector : IDataProtector
    {
        private readonly string[] _purpose =
        {
            typeof(OAuthAuthorizationServerMiddleware).Namespace,
            "Access_Token",
            "v1"
        };

        public byte[] Protect(byte[] userData)
        {
            throw new NotImplementedException();
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            return System.Web.Security.MachineKey.Unprotect(protectedData, _purpose);
        }
    }
}