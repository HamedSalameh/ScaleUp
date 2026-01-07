using LanguageExt.Common;
using MediatR;

namespace Auth.Application.Features.Signout
{
    public class SignoutCommand : IRequest<Result<bool>>
    {
        public SignoutRequest Request { get; }

        public SignoutCommand(SignoutRequest request)
        {
            Request = request ?? throw new ArgumentNullException(nameof(request));
        }
    }
}
