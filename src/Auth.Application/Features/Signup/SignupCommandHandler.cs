using Auth.Infrastructure.KeyCloak;
using FluentResults;
using MediatR;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth.Application.Features.Signup
{
    public class SignupCommandHandler : IRequestHandler<SignupCommand, Result<SignupResponse>>
    {
        private readonly ILogger<SignupCommandHandler> _logger;
        private readonly IKeyCloakService _keyCloakService;

        public SignupCommandHandler(ILogger<SignupCommandHandler> logger, IKeyCloakService keyCloakService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _keyCloakService = keyCloakService ?? throw new ArgumentNullException(nameof(keyCloakService));
        }

        public async Task<Result<SignupResponse>> Handle(SignupCommand request, CancellationToken cancellationToken)
        {
            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Handling SignupCommand for user: {email}", request.email);
            }

            if (request == null)
            {
                _logger.LogError("SignupCommand request is null");
                return Result.Fail("Invalid signup request");
            }

            try
            {
                var createUserResult = await _keyCloakService.CreateUserAsync(request.email, request.password, request.firstName, request.lastName, cancellationToken);

                if (createUserResult.IsSuccess)
                {
                    _logger.LogInformation("User {email} created successfully in KeyCloak", request.email);
                    return Result.Ok(new SignupResponse());
                }
                else
                {
                    _logger.LogError("Failed to create user {email} in KeyCloak: {errors}", request.email, string.Join(", ", createUserResult.Errors.Select(e => e.Message)));
                    return Result.Fail("Failed to create user");
                }
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Exception occurred while creating user {email} in KeyCloak", request.email);
                return Result.Fail<SignupResponse>("An unexpected error while trying to create user");
            } 
        }
    }
}
