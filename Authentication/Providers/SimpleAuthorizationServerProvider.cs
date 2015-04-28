﻿using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Authentication.Entities;
using Authentication.Models;
using Authentication.Util;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

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

            using (AuthRepository repo = new AuthRepository(context.OwinContext))
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

            using (AuthRepository repo = new AuthRepository(context.OwinContext))
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
            }

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { 
                        "as:client_id", context.ClientId ?? string.Empty
                    },
                    { 
                        "userName", context.UserName
                    }
                });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);

        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);

            //var newClaim = newIdentity.Claims.FirstOrDefault(c => c.Type == "newClaim");
            //if (newClaim != null)
            //{
            //    newIdentity.RemoveClaim(newClaim);
            //}
            //newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
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