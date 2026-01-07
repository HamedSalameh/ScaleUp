
using FastEndpoints;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Features.Signout
{
    public class SignoutEndpoint : Endpoint<SignoutRequest>
    {
        private readonly ILogger<SignoutEndpoint> _logger;
        private readonly ISender _sender;

        public SignoutEndpoint(ISender sender, ILogger<SignoutEndpoint> logger)
        {
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public override void Configure()
        {
            Post("/signout");
            AllowAnonymous();

            Summary(s =>
            {
                s.Summary = "User Signout";
                s.Description = "Endpoint for user signout that invalidates tokens.";
                s.Response(204, "Successful signout.");
            });

            Options(o =>
            {
                o.ProducesProblemDetails(400);
                o.Produces(StatusCodes.Status204NoContent);
                o.Produces(StatusCodes.Status500InternalServerError);
                o.Produces(StatusCodes.Status401Unauthorized);
            });
        }

        public override async Task HandleAsync(SignoutRequest signoutRequest, CancellationToken ct)
        {
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Received signout request for user: {UserId}", signoutRequest.UserId);
            }

            var signoutCommand = new SignoutCommand(signoutRequest);
            var response = await _sender.Send(signoutCommand, ct);

            if (response.IsFaulted)
            {
                _logger.LogInformation("Signout failed for user {UserId}: {Error}", signoutRequest.UserId, response.ToString());
                var error = response.Match(_ => "", ex => ex.Message);

                AddError(error);

                await Send.ErrorsAsync(StatusCodes.Status400BadRequest, ct);
                return;
            }

            _logger.LogInformation("User {UserId} signed out successfully.", signoutRequest.UserId);
            await Send.NoContentAsync(ct);
        }
    }
}
