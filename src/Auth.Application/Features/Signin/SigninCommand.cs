using LanguageExt.Common;
using MediatR;

namespace Auth.Application.Features.Signin
{
    public record SigninCommand(SigninRequest SigninRequest) : IRequest<Result<SigninResponse>>;
}
