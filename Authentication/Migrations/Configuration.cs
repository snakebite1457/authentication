using System.Collections.Generic;
using System.Data.Entity.Migrations;
using System.Linq;
using Authentication.Entities;
using Authentication.Models;
using Authentication.Util;
using Microsoft.AspNet.Identity.EntityFramework;

namespace Authentication.Migrations
{
    internal sealed class Configuration : DbMigrationsConfiguration<AuthContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = true;
            AutomaticMigrationDataLossAllowed = true;
        }

        protected override void Seed(AuthContext context)
        {
            if (context.Clients.Any())
            {
                return;
            }

            context.Clients.AddRange(BuildClientsList());
            BuildIdentityRoles().ToList().ForEach(role => context.Roles.Add(role));
            context.SaveChanges();
        }

        private static IEnumerable<Client> BuildClientsList()
        {
            var clientsList = new List<Client>
            {
                new Client
                {
                    Id = "subPrintApp",
                    Secret = Helper.GetHash("abc@123"),
                    Name = "AngularJS front-end Application",
                    ApplicationType = ApplicationTypes.JavaScript,
                    Active = true,
                    RefreshTokenLifeTime = 7200,
                    AllowedOrigin = "http://localhost:29184"
                },
                new Client
                {
                    Id = "consoleApp",
                    Secret = Helper.GetHash("123@abc"),
                    Name = "Console Application",
                    ApplicationType = ApplicationTypes.NativeConfidential,
                    Active = true,
                    RefreshTokenLifeTime = 14400,
                    AllowedOrigin = "*"
                }
            };

            return clientsList;
        }

        private static IEnumerable<IdentityRole> BuildIdentityRoles()
        {
            var identityRoles = new List<IdentityRole>
            {
                new IdentityRole("Member"),
                new IdentityRole("Leader"),
                new IdentityRole("Admin")
            };

            return identityRoles;
        }
    }
}