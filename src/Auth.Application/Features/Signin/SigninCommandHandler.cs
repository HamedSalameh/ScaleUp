using Auth.Domain.Models;
using Auth.Infrastructure.KeyCloak;
using FluentResults;
using MediatR;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Application.Features.Signin
{
    public class SigninCommandHandler : IRequestHandler<SigninCommand, Result<SigninResponse>>
    {
        private const string BearerTokenType = "Bearer";

        private readonly ILogger<SigninCommandHandler> _logger;
        private readonly IKeyCloakService _keyCloakService;
        private readonly KeycloakOptions _keycloakOptions;

        public SigninCommandHandler(
            ILogger<SigninCommandHandler> logger,
            IKeyCloakService keyCloakService,
            IOptions<KeycloakOptions> keycloakOptions)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _keyCloakService = keyCloakService ?? throw new ArgumentNullException(nameof(keyCloakService));
            _keycloakOptions = keycloakOptions?.Value ?? throw new ArgumentNullException(nameof(keycloakOptions));
        }

        public async Task<Result<SigninResponse>> Handle(SigninCommand request, CancellationToken cancellationToken)
        {
            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Handling SigninCommand for user: {Username}", request.SigninRequest.Username);
            }

            try
            {
                var tokenResult = await _keyCloakService.SigninAsync(request.SigninRequest.Username, request.SigninRequest.Password, cancellationToken);

                if (tokenResult.IsFailed)
                {
                    // Combine all errors from FluentResults
                    var errorMessage = string.Join(", ", tokenResult.Errors.Select(e => e.Message));
                    _logger.LogWarning("Signin failed for user {Username}: {Errors}", request.SigninRequest.Username, errorMessage);

                    return Result.Fail<SigninResponse>(errorMessage);
                }

                // Build SigninResponse
                var signinResponse = new SigninResponse(new TokenResponse
                {
                    AccessToken = tokenResult.Value ?? string.Empty,
                    TokenType = BearerTokenType,
                    ExpiresIn = _keycloakOptions.AccessTokenLifetimeMinutes,
                    ExpiresAtUtc = DateTime.UtcNow.AddMinutes(_keycloakOptions.AccessTokenLifetimeMinutes)
                });

                _logger.LogInformation(
                    "User {Username} signed in successfully. Token expires in {Minutes} minutes at {ExpiresAtUtc}.",
                    request.SigninRequest.Username,
                    signinResponse.Token!.ExpiresIn,
                    signinResponse.Token!.ExpiresAtUtc
                );

                return Result.Ok(signinResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during signin for user {Username}", request.SigninRequest.Username);
                return Result.Fail<SigninResponse>("An unexpected error occurred. Please try again later.");
            }
        }
    }
}

