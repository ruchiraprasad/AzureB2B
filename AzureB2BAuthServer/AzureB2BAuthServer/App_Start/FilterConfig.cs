﻿using System.Web;
using System.Web.Mvc;

namespace AzureB2BAuthServer
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}