using FastEndpoints;
using FluentValidation;

namespace Auth.Application.Features.Signin
{
    public class SigninValidator : Validator<SigninRequest>
    {
        public SigninValidator()
        {
            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("Username is required.")
                .MinimumLength(3).WithMessage("Username must be at least 3 characters long.");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password is required.");
        }
    }
}
