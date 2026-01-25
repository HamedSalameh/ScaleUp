using System.ComponentModel.DataAnnotations;

namespace Auth.Application.Features.Signup
{
    public sealed class SignupRequest
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }

        [Required]
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;

        public SignupRequest(string email, string password, string firstName, string lastName)
        {
            Email = email;
            Password = password;
            FirstName = firstName;
            LastName = lastName;
        }

        public SignupRequest() : this(string.Empty, string.Empty, string.Empty, string.Empty) { }
    }
}
