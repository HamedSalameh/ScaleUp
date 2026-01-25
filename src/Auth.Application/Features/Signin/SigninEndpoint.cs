using FastEndpoints;
using FluentResults;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Auth.Application.Features.Signin;

public class SigninEndpoint : Endpoint<SigninRequest, SigninResponse>
{
    private readonly ISender _sender;

    public SigninEndpoint(ISender sender)
    {
        _sender =  sender ?? throw new ArgumentNullException(nameof(sender));
    }

    public override void Configure()
    {
        Post("/api/signin"); // or specify your pattern like "/signin"
        AllowAnonymous();
        Description(b => b
            .Produces<SigninResponse>(200)
            .Produces<SigninResponse>(400)
            .Produces<SigninResponse>(401)
            .Produces<SigninResponse>(500));
    }

    public override async Task HandleAsync(SigninRequest request, CancellationToken ct)
    {
        Logger.LogInformation("Signin attempt for: {Username}", request.Username);

        // 1. Send command (Returns Result<SigninResponse>)
        Result<SigninResponse> result = await _sender.Send(new SigninCommand(request), ct);

        // 2. Handle Failure
        if (result.IsFailed)
        {
            Logger.LogWarning("Signin failed for user {Username}: {Errors}",
                request.Username,
                result.Errors.Select(e => e.Message));

            // add the errors to the response
            foreach (var error in result.Errors)
            {
                AddError(error.Message);
            }

            await Send.ErrorsAsync(400, ct);
            return;
        }

        // 3. Handle Success
        Logger.LogInformation("User {Username} signed in successfully", request.Username);
        await Send.OkAsync(result.Value, ct);
    }
}