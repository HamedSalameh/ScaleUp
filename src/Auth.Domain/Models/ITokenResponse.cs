namespace Auth.Domain.Models
{
    public interface ITokenResponse
    {
        string IdToken { get; init; }
        string AccessToken { get; init; }
        string RefreshToken { get; init; }
        int ExpiresIn { get; init; }
        string TokenType { get; init; }
    }
}
