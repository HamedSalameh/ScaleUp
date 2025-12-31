using LanguageExt.Common;
using MediatR;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Features.Signout
{
    public class SignoutCommandHandler : IRequestHandler<SignoutCommand, Result<bool>>
    {
        private readonly ILogger<SignoutCommandHandler> _logger;
        // Add your repositories/services here

        public SignoutCommandHandler(ILogger<SignoutCommandHandler> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<Result<bool>> Handle(SignoutCommand request, CancellationToken cancellationToken)
        {
            try
            {
                _logger.LogInformation("Processing signout for user: {UserId}", request.Request.UserId);

                // Implement your signout logic here:
                // - Invalidate refresh token
                // - Blacklist access token
                // - Clear session data

                return new Result<bool>(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during signout for user: {UserId}", request.Request.UserId);
                return new Result<bool>(ex);
            }
        }
    }
}
