using System;
using System.Configuration;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Authentication.Util;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.DataProtection;
using SendGrid;

namespace Authentication
{
    public class EmailService : IIdentityMessageService
    {
        public async Task SendAsync(IdentityMessage message)
        {
            // Plug in your email service here to send an email.
            await ConfigSendGridasync(message);
        }

        // Use NuGet to install SendGrid (Basic C# client lib) 
        private static async Task ConfigSendGridasync(IdentityMessage message)
        {
            var sendGridMessage = new SendGridMessage();
            //myMessage.AddTo(message.Destination);
           
            
            // Debug
            sendGridMessage.AddTo("dennis.mail206@gmail.com");

            sendGridMessage.From = new MailAddress("norepley@subprint.de", "SubPrint");
            sendGridMessage.Subject = message.Subject;
            sendGridMessage.Text = message.Body;
            sendGridMessage.Html = message.Body;

            var credentials = new NetworkCredential(
                ConfigurationManager.AppSettings["mailAccount"],
                ConfigurationManager.AppSettings["mailPassword"]
                );

            // Create a Web transport for sending email.
            var transportWeb = new Web(credentials);

            // Send the email.
            await transportWeb.DeliverAsync(sendGridMessage);
        }
    }

    // Configure the application user manager which is used in this application.
    public class ApplicationUserManager : UserManager<IdentityUser>
    {
        public ApplicationUserManager(IUserStore<IdentityUser> store)
            : base(store)
        {
        }


        public static ApplicationUserManager Create(AuthContext context)
        {
            var provider = new DpapiDataProtectionProvider("Sample");

            var manager = new ApplicationUserManager(new UserStore<IdentityUser>(context));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<IdentityUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireDigit = true
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<IdentityUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            manager.EmailService = new EmailService();

            manager.UserTokenProvider = new DataProtectorTokenProvider<IdentityUser>(provider.Create("EmailConfirmation"));
            return manager;
        }
    }
}