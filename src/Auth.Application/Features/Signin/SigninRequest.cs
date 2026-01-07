using System.ComponentModel.DataAnnotations;

namespace Auth.Application.Features.Signin
{
    public class SigninRequest
    {
        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }

        public SigninRequest() : this(string.Empty, string.Empty) { } 

        public SigninRequest(string username, string password)
        {
            Username = username;
            Password = password;
        }
    }
}
