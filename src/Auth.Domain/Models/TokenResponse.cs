namespace Auth.Domain.Models
{
    public sealed class TokenResponse : ITokenResponse
    {
        private const string NotSet = "Not Set";

        public string IdToken { get; init; } = NotSet;
        public string RefreshToken { get; init; } = NotSet;
        public string AccessToken { get; init; } = NotSet;
        public int ExpiresIn { get; init; } = 0;
        public string TokenType { get; init; } = NotSet;
    }
}
