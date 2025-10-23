using Auth.Domain.Models;
using FastEndpoints;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Features.Signin
{
    // Using FastEndpoints to define the endpoint for Signin
    public class SigninEndpoint : Endpoint<SigninRequest, SigninResponse>
    {
        private readonly ILogger _logger;
        private readonly ISender _sender;

        public SigninEndpoint(ISender sender, ILogger logger)
        {
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public override void Configure()
        {
            Post("/signin");
            AllowAnonymous();
            // Define the summary and description for Swagger documentation
            Summary(s =>
            {
                s.Summary = "User Signin";
                s.Description = "Endpoint for user signin that returns tokens.";
                s.Response<SigninResponse>(200, "Successful signin returns tokens.");
                s.Params.Add("Username", "The username of the user.");
                s.Params.Add("Password", "The password of the user.");
            });

            // Define the request and response types along with possible status codes
            Options(o =>
            {
                o.ProducesProblemDetails(400);
                o.Produces<SigninResponse>(200);
                o.Produces(StatusCodes.Status500InternalServerError);
                o.Produces(StatusCodes.Status401Unauthorized);
                o.Produces(StatusCodes.Status403Forbidden);
            });
        }

        // return the SigninResponse
        public override async Task HandleAsync(SigninRequest signinRequest, CancellationToken ct)
        {
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Received signin request for user: {Username}", signinRequest.Username);
            }

            var signinCommand = new SigninCommand(signinRequest);
            var response = await _sender.Send(signinCommand, ct);

            if (response.IsFaulted)
            {
                _logger.LogInformation("Signin failed for user {Username}: {Error}", signinRequest.Username, response.ToString());
                var error = response.Match(_ => "", ex => ex.Message);

                AddError(error);

                await Send.ErrorsAsync(StatusCodes.Status400BadRequest, ct);
                return;
            }

            var signinResponse = response.Match(res => res, ex => new SigninResponse(new TokenResponse()));

            _logger.LogInformation("User {Username} signed in successfully.", signinRequest.Username);
            await Send.OkAsync(signinResponse, ct);
        }
    }
}
