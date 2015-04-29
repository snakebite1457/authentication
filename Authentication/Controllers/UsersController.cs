using System.Linq;
using System.Web;
using System.Web.Http;
using AuthenticationContext.Models;
using AuthenticationContext.Util;

namespace Authentication.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class UsersController : ApiController
    {
        private readonly AuthRepository _repo;

        public UsersController()
        {
            _repo = new AuthRepository(HttpContext.Current.GetOwinContext());
        }

        [Authorize(Roles = "Admin")]
        public IHttpActionResult GetUsers()
        {
            var identityUsers = _repo.GetAllUsers();
            var users = identityUsers.Select(user => new UserModel()
            {
                UserId = user.Id, UserName = user.UserName
            }).ToList();

            return Json(users);
        } 
    }
}
