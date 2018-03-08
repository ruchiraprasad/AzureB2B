using System;
using System.Collections.Concurrent;
using System.Configuration;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(AzureB2BAuthServer.Startup))]

namespace AzureB2BAuthServer
{
    public class Startup
    {
        // Microsoft.Owin
        // Microsoft.Owin.Cors
        // Microsoft.Owin.Host.SystemWeb
        // Microsoft.Owin.Security
        // Microsoft.Owin.Security.Cookies
        // Microsoft.Owin.Security.OAuth
        // Microsoft.Owin.Security.OpenIdConnect

        public void Configuration(IAppBuilder app)
        {
            string authorizePath = ConfigurationManager.AppSettings["B2B:AuthorizePath"];
            string tokenPath = ConfigurationManager.AppSettings["B2B:TokenPath"];
            string loginPath = ConfigurationManager.AppSettings["B2B:LoginPath"];
            string logoutPath = ConfigurationManager.AppSettings["B2B:LogoutPath"];
            string mePath = ConfigurationManager.AppSettings["B2B:MePath"];

            string clientId = ConfigurationManager.AppSettings["B2B:ClientId"];
            string aadInstance = ConfigurationManager.AppSettings["B2B:AADInstance"];
            string tenantId = ConfigurationManager.AppSettings["B2B:TenantId"];
            string redirectUri = ConfigurationManager.AppSettings["B2B:RedirectUri"];
            string postLogoutRedirectUri = ConfigurationManager.AppSettings["B2B:PostLogoutRedirectUri"];
            string authority = aadInstance + tenantId;

            // Enable Application Sign In Cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Application",
                AuthenticationMode = AuthenticationMode.Passive,
                LoginPath = new PathString(loginPath),
                LogoutPath = new PathString(logoutPath),
            });

            // Enable External Sign In Cookie
            app.SetDefaultSignInAsAuthenticationType("External");
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "External",
                AuthenticationMode = AuthenticationMode.Passive,
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "External",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
            });

            app.UseOpenIdConnectAuthentication( new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
        #if SingleTenantApp
                            Authority = String.Format(CultureInfo.InvariantCulture, ConfigHelper.AadInstance, ConfigHelper.Tenant), // For Single-Tenant
        #else
                Authority = authority, // For Multi-Tenant
        #endif
                PostLogoutRedirectUri = postLogoutRedirectUri,
                RedirectUri = redirectUri,
                Caption = "Azure Active Directory B2B",
                // Here, we've disabled issuer validation for the multi-tenant sample.  This enables users
                // from ANY tenant to sign into the application (solely for the purposes of allowing the sample
                // to be run out-of-the-box.  For a real multi-tenant app, reference the issuer validation in 
                // WebApp-MultiTenant-OpenIDConnect-DotNet.  If you're running this sample as a single-tenant
                // app, you can delete the ValidateIssuer property below.
                TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
        #if !SingleTenantApp
                    ValidateIssuer = false, // For Multi-Tenant Only
        #endif
                    RoleClaimType = "roles",
                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = context =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect("/Error/ShowError?signIn=true&errorMessage=" + context.Exception.Message);
                        return Task.FromResult(0);
                    }
                }
            });

            // Setup Authorization Server
            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString(authorizePath),
                TokenEndpointPath = new PathString(tokenPath),
                ApplicationCanDisplayErrors = true,
                AllowInsecureHttp = true,
                //#if DEBUG
                //                AllowInsecureHttp = true,
                //#endif
                // Authorization server provider which controls the lifecycle of Authorization Server
                Provider = new OAuthAuthorizationServerProvider
                {
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,
                    OnValidateClientAuthentication = ValidateClientAuthentication,
                    OnGrantResourceOwnerCredentials = GrantResourceOwnerCredentials,
                    OnGrantClientCredentials = GrantClientCredetails
                },

                // Authorization code provider which creates and receives authorization code
                AuthorizationCodeProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode,
                },

                // Refresh token provider which creates and receives referesh token
                RefreshTokenProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken,
                }
            });
        }

        private Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            context.Validated();
            //var task = Task.Run(async () => await Application.GetApplicationByName(context.ClientId));
            //var application = "Service Request";
            //if (context.ClientId == "Service Request")
            //{
            //    HttpContext.Current.Session["ApplicationId"] = context.ClientId;
            //    context.Validated("http://localhost:38501/Account");
            //}

            return Task.FromResult(0);
        }

        private Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;
            if (context.TryGetBasicCredentials(out clientId, out clientSecret) || context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                context.Validated();
                //var task = Task.Run(async () => await Application.GetApplicationByName(clientId));
                //var application = "Service Request";
                //if (clientId == "Service Request" && clientSecret == "7890ab")
                //{
                //    context.Validated();
                //}
            }
            return Task.FromResult(0);
        }

        private Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var identity = new ClaimsIdentity(new GenericIdentity(context.UserName, OAuthDefaults.AuthenticationType), context.Scope.Select(x => new Claim("urn:oauth:scope", x)));

            context.Validated(identity);

            return Task.FromResult(0);
        }

        private Task GrantClientCredetails(OAuthGrantClientCredentialsContext context)
        {
            var identity = new ClaimsIdentity(new GenericIdentity(context.ClientId, OAuthDefaults.AuthenticationType), context.Scope.Select(x => new Claim("urn:oauth:scope", x)));

            context.Validated(identity);

            return Task.FromResult(0);
        }


        private readonly ConcurrentDictionary<string, string> _authenticationCodes =
            new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            _authenticationCodes[context.Token] = context.SerializeTicket();
        }

        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            string value;
            if (_authenticationCodes.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }
        }

        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            context.SetToken(context.SerializeTicket());
        }

        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
        }
    }
}
