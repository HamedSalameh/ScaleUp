
using FluentResults;

namespace Auth.Infrastructure.KeyCloak
{
    public interface IKeyCloakService
    {
        Task<Result<string>> SigninAsync(string username, string password, CancellationToken cancellationToken);
    }
}
