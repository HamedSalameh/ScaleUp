using Auth.Domain.Models;

namespace Auth.Application.Features.Signin
{
    public class SigninResponse
    {
        public ITokenResponse? Token { get; set; }
        // Signin errors can be added here if needed
        public string? Errors { get; set; } = null;

        public SigninResponse() : this(null!) { }

        public SigninResponse(ITokenResponse token)
        {
            Token = token;
            Errors = null;
        }
    }
}
