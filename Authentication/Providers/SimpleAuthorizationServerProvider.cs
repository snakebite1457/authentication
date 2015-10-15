using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Helpers;
using AuthenticationContext.Entities;
using AuthenticationContext.Models;
using AuthenticationContext.Util;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using WebGrease.Css.Extensions;

namespace Authentication.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        Client _client;

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            string clientId;
            string clientSecret;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                //Remove the comments from the below line context.SetError, and invalidate context 
                //if you want to force sending clientId/secrects once obtain access tokens. 
                context.SetError("invalid_clientId", "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            using (AuthRepository repo = new AuthRepository(context.OwinContext, Startup.DataProtectionProvider))
            {
                _client = repo.FindClient(context.ClientId);
            }

            if (_client == null)
            {
                context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            if (_client.ApplicationType == ApplicationTypes.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError("invalid_clientId", "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (_client.Secret != Helper.GetHash(clientSecret))
                    {
                        context.SetError("invalid_clientId", "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!_client.Active)
            {
                context.SetError("invalid_clientId", "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            context.OwinContext.Set("as:clientAllowedOrigin", _client.AllowedOrigin);
            context.OwinContext.Set("as:clientRefreshTokenLifeTime", _client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin") ?? "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);


            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { 
                        "as:client_id", context.ClientId ?? string.Empty
                    }
                }
            );

            using (AuthRepository repo = new AuthRepository(context.OwinContext, Startup.DataProtectionProvider))
            {
                // Require the user to have a confirmed email before they can log on.
                var user = await repo.FindUser(context.UserName, context.Password);
                if (user != null)
                {
                    if (!await repo.IsUserConfirmed(user))
                    {
                        await repo.SendEmailConfirmationTokenEmail(user.Id, _client.AllowedOrigin);
                        context.SetError("", "You must have a confirmed email to log on. The confirmation token has been resent to your email account.");
                        return;
                    }
                }
                else
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }

                identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));

                foreach (var role in await repo.GetUserRoles(user.Id))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }

                identity.AddClaim(new Claim("sub", context.UserName));

                props.Dictionary.Add(new KeyValuePair<string, string>
                (
                    "email", user.Email
                ));

                props.Dictionary.Add(new KeyValuePair<string, string>
                (
                    "username", user.UserName
                ));

                props.Dictionary.Add(new KeyValuePair<string, string>
               (
                   "roles", Json.Encode((await repo.GetUserRoles(user.Id)))
               ));
            }

            var ticket = new AuthenticationTicket(identity, props);

            //var currentUtc = new SystemClock().UtcNow;
            //ticket.Properties.IssuedUtc = currentUtc;
            //ticket.Properties.ExpiresUtc = currentUtc.Add(TimeSpan.FromSeconds(90));

            context.Validated(ticket);

        }

        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return;
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);

            var currentRole = newIdentity.Claims.Where(c => c.Type == ClaimTypes.Role);
            foreach (var role in currentRole)
            {
                newIdentity.RemoveClaim(role);
            }

            using (AuthRepository repo = new AuthRepository(context.OwinContext, Startup.DataProtectionProvider))
            {
                var user = repo.FindUser(context.Ticket.Identity.Name);
                foreach (var role in await repo.GetUserRoles(user.Id))
                {
                    newIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
                }
            }

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);

            context.Validated(newTicket);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }
    }
}