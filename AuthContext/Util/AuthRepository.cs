using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using AuthenticationContext.Entities;
using AuthenticationContext.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;

namespace AuthenticationContext.Util
{
    public class AuthRepository : IDisposable
    {
        private readonly AuthContext _authContext;
        private readonly ApplicationUserManager _userManager;

        public AuthRepository(IOwinContext context)
        {
            _authContext = new AuthContext();
            _userManager = context.GetUserManager<ApplicationUserManager>() ?? ApplicationUserManager.Create(_authContext);
        }

        public IEnumerable<IdentityUser> GetAllUsers()
        {
            return _userManager.Users;
        } 

        public async Task<IdentityUser> FindUser(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                user = await _userManager.FindAsync(user.UserName, password);
            }
            
            return user;
        }

        public async Task<bool> IsUserConfirmed(IdentityUser user)
        {
            return await _userManager.IsEmailConfirmedAsync(user.Id);
        }

        public async Task SendEmailAsync(string userId, string subject, string body)
        {
            await _userManager.SendEmailAsync(userId, subject, body);
        }

        public async Task SendEmailConfirmationTokenEmail(string userId, string host)
        {

            var user = _userManager.FindByIdAsync(userId);
            string code = await _userManager.GenerateEmailConfirmationTokenAsync(userId);
            var callbackUrl = string.Format("Please confirm your email by clicking <a href=\"{0}/#confirmemail?userId={1}&code={2}\">here</a>",
                   host, user.Id, HttpUtility.UrlEncode(code));

            await SendEmailAsync(userId, "Confirm your account", callbackUrl);
        }

        public async Task<IdentityResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            if (user == null)
            {
                return null;
            }
            return await _userManager.ResetPasswordAsync(user.Id, resetPasswordModel.Code, resetPasswordModel.Password);
        }

        public async Task<string> ForgotPassword(ForgotPasswordModel forgotPasswordModel)
        {
            var user = await _userManager.FindByEmailAsync(forgotPasswordModel.Email);
            if (user != null && (await _userManager.IsEmailConfirmedAsync(user.Id)))
            {
                var client = await _authContext.Clients.FindAsync(forgotPasswordModel.ClientId);
                if (client == null)
                {
                    return "Client not found!";
                }

                string code = await _userManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = string.Format("Please reset your password by clicking <a href=\"{0}/#resetpassword?userId={1}&code={2}\">here</a>",
                    client.AllowedOrigin, user.Id, HttpUtility.UrlEncode(code));

                await SendEmailAsync(user.Id, "Reset Password", callbackUrl);
            }

            return "Please check your email to reset your password."; 
        }

        public async Task<IdentityResult> ConfirmEmail(string userId, string code)
        {
            return await _userManager.ConfirmEmailAsync(userId, code);
        }

        public Client FindClient(string clientId)
        {
            var client = _authContext.Clients.Find(clientId);

            return client;
        }

        public async Task<IEnumerable<string>> GetUserRoles(string userId)
        {
            return await _userManager.GetRolesAsync(userId);
        } 

        public async Task<IdentityResult> RegisterUser(RegisterModel registerModel)
        {
            IdentityUser user = new IdentityUser
            {
                UserName = registerModel.Username,
                Email = registerModel.Email
            };

            var result = await _userManager.CreateAsync(user, registerModel.Password);
            if (result.Succeeded)
            {
                var client = await _authContext.Clients.FindAsync(registerModel.ClientId);
                if (client == null)
                {
                    return null;
                }

                var currentUser = _userManager.FindByEmail(registerModel.Email);
                await _userManager.AddToRoleAsync(currentUser.Id, "Member");

                await SendEmailConfirmationTokenEmail(currentUser.Id, client.AllowedOrigin);
            }

            return result;
        }

        public async Task<bool> AddRefreshToken(RefreshToken token)
        {

            var existingToken = _authContext.RefreshTokens.SingleOrDefault(r => r.Subject == token.Subject && r.ClientId == token.ClientId);

            if (existingToken != null)
            {
                var result = await RemoveRefreshToken(existingToken);
            }

            _authContext.RefreshTokens.Add(token);

            return await _authContext.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemoveRefreshToken(string refreshTokenId)
        {
            var refreshToken = await _authContext.RefreshTokens.FindAsync(refreshTokenId);

            if (refreshToken != null)
            {
                _authContext.RefreshTokens.Remove(refreshToken);
                return await _authContext.SaveChangesAsync() > 0;
            }

            return false;
        }

        public async Task<bool> RemoveRefreshToken(RefreshToken refreshToken)
        {
            _authContext.RefreshTokens.Remove(refreshToken);
            return await _authContext.SaveChangesAsync() > 0;
        }

        public async Task<RefreshToken> FindRefreshToken(string refreshTokenId)
        {
            var refreshToken = await _authContext.RefreshTokens.FindAsync(refreshTokenId);

            return refreshToken;
        }

        public List<RefreshToken> GetAllRefreshTokens()
        {
            return _authContext.RefreshTokens.ToList();
        }

        public async Task<IdentityUser> FindAsync(UserLoginInfo loginInfo)
        {
            IdentityUser user = await _userManager.FindAsync(loginInfo);

            return user;
        }

        public async Task<IdentityResult> CreateAsync(IdentityUser user)
        {
            var result = await _userManager.CreateAsync(user);

            return result;
        }

        public async Task<IdentityResult> AddLoginAsync(string userId, UserLoginInfo login)
        {
            var result = await _userManager.AddLoginAsync(userId, login);

            return result;
        }

        public void Dispose()
        {
            _authContext.Dispose();
            _userManager.Dispose();
        }
    }
}