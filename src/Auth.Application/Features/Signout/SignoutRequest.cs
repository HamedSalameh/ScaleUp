using System.ComponentModel.DataAnnotations;

namespace Auth.Application.Features.Signout
{
    public class SignoutRequest
    {
        [Required]
        public string UserId { get; set; }

        public string? RefreshToken { get; set; }

        public SignoutRequest() : this(string.Empty)
        {
        }

        public SignoutRequest(string userId, string? refreshToken = null)
        {
            UserId = userId;
            RefreshToken = refreshToken;
        }
    }
}
