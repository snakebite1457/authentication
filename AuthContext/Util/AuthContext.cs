using System.Data.Entity;
using AuthenticationContext.Entities;
using AuthenticationContext.Migrations;
using Microsoft.AspNet.Identity.EntityFramework;

namespace AuthenticationContext.Util
{
    public class AuthContext : IdentityDbContext<IdentityUser>
    {
        public AuthContext()
            : base("name=AuthContext") 
        {
            //Database.SetInitializer(new MigrateDatabaseToLatestVersion<AuthContext, Configuration>());
            Database.SetInitializer(new AuthContextDbInit());
        }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}