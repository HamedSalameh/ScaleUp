using Auth.Domain.Models;

namespace Auth.Application.Features.Signin
{
    public class SigninResponse
    {
        public ITokenResponse Token { get; set; }
        public SigninResponse(ITokenResponse token)
        {
            Token = token;
        }
    }
}
