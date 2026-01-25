
using FluentResults;

namespace Auth.Infrastructure.KeyCloak
{
    public interface IKeyCloakService
    {
        Task<Result<string>> CreateUserAsync(string email, string password, string firstName, string lastName, CancellationToken cancellationToken);
        Task<Result<string>> SigninAsync(string username, string password, CancellationToken cancellationToken);
    }
}
