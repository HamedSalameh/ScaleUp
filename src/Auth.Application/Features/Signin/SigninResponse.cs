using Auth.Domain.Models;

namespace Auth.Application.Features.Signin
{
    /// <summary>
    /// Represents the result of a sign-in operation, including authentication tokens and any associated errors.
    /// </summary>
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
