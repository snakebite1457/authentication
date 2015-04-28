using System.ComponentModel.DataAnnotations;

namespace Authentication.Models
{
        public class ExternalLoginViewModel
        {
            public string Name { get; set; }

            public string Url { get; set; }

            public string State { get; set; }
        }

        public class RegisterExternalBindingModel
        {
            [Required]
            public string UserName { get; set; }

            [Required]
            public string Provider { get; set; }

            [Required]
            public string ExternalAccessToken { get; set; }

        }

        public class ParsedExternalAccessToken
        {
            public string UserId { get; set; }
            public string AppId { get; set; }
        }
}