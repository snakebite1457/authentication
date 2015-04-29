using System.Data.Entity;
using AuthenticationContext.Entities;
using Microsoft.AspNet.Identity.EntityFramework;

namespace AuthenticationContext.Util
{
    public class AuthContext : IdentityDbContext<IdentityUser>
    {
        public AuthContext()
            : base("AuthContext")
        {

        }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}