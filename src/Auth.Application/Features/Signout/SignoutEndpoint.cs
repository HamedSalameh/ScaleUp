using FastEndpoints;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Features.Signout
{
    public class SignoutEndpoint : Endpoint<SignoutRequest>
    {
        private readonly ISender _sender;

        public SignoutEndpoint(ISender sender)
        {
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
        }

        public override void Configure()
        {
            Post("/api/signout");
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
            if (Logger.IsEnabled(LogLevel.Information))
            {
                Logger.LogInformation("Received signout request for user: {UserId}", signoutRequest.UserId);
            }

            var signoutCommand = new SignoutCommand(signoutRequest);
            var response = await _sender.Send(signoutCommand, ct);

            if (response.IsFailed)
            {
                Logger.LogInformation("Signout failed for user {UserId}: {Error}", signoutRequest.UserId, response.ToString());

                foreach (var error in response.Errors)
                {
                    AddError(error.Message);
                }

                await Send.ErrorsAsync(400, ct);
                return;
            }

            Logger.LogInformation("User {UserId} signed out successfully.", signoutRequest.UserId);
            await Send.NoContentAsync(ct);
        }
    }
}