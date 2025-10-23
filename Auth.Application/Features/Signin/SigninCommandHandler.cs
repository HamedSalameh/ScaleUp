using Auth.Domain.Models;
using LanguageExt.Common;
using MediatR;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Features.Signin
{
    public class SigninCommandHandler : IRequestHandler<SigninCommand, Result<SigninResponse>>
    {
        private readonly ILogger<SigninCommandHandler> _logger;
        public SigninCommandHandler(ILogger<SigninCommandHandler> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task<Result<SigninResponse>> Handle(SigninCommand request, CancellationToken cancellationToken)
        {
            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Handling SigninCommand for user: {Username}", request.SigninRequest.Username);
            }

            // create a dummy TokenResponse
            var tokenResponse = new TokenResponse
            {
                IdToken = "dummy-id-token",
                AccessToken = "dummy-access-token",
                RefreshToken = "dummy-refresh-token",
                ExpiresIn = 3600,
                TokenType = "Bearer"
            };

            _logger.LogInformation("User {Username} signed in successfully.", request.SigninRequest.Username);
            var signinResponse = new SigninResponse(tokenResponse);

            return Task.FromResult<Result<SigninResponse>>(signinResponse);
        }
    }
}
