using FastEndpoints;
using FluentResults;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;

namespace Auth.Application.Features.Signup
{
    public sealed class SignupEndpoint : Endpoint<SignupRequest, SignupResponse>
    {
        private readonly ISender _sender;

        public SignupEndpoint(ISender sender)
        {
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
        }

        public override void Configure()
        {
            Post("/api/signup");
            AllowAnonymous();
            Description(b => b
                .Produces((int)HttpStatusCode.OK)
                .Produces((int)HttpStatusCode.BadRequest)
                .Produces((int)HttpStatusCode.Forbidden));

        }

        public override async Task HandleAsync(SignupRequest request, CancellationToken ct)
        {
            Logger.LogInformation("Handling signup request for email: {Email}", request.Email);

            var command = new SignupCommand(request.Email, request.Password, request.FirstName, request.LastName);

            Result<SignupResponse> result = await _sender.Send(command, ct);

            if (result.IsFailed)
            {
                // Handle failure (e.g., return BadRequest or Forbidden)
            }

            Logger.LogInformation("Signup successful for email: {Email}", request.Email);
            await Send.OkAsync(new SignupResponse(), ct);
        }

    }

    public class SignupResponse
    {

    }
}
