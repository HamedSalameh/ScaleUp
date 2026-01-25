using FluentResults;
using MediatR;

namespace Auth.Application.Features.Signup
{
    public class SignupCommand : IRequest<Result<SignupResponse>>
    {
        public string email { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
        public string firstName { get; set; } = string.Empty;
        public string lastName { get; set; }

        public SignupCommand(string email, string password, string firstName, string lastName)
        {
            this.email = email;
            this.password = password;
            this.firstName = firstName;
            this.lastName = lastName;
        }
    }
}
