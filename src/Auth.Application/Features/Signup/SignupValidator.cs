

using Auth.Domain;
using FastEndpoints;
using FluentValidation;

namespace Auth.Application.Features.Signup
{
    public class SignupValidator : Validator<SignupRequest>
    {
        public SignupValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email is required.")
                .MinimumLength(AuthConstants.MinEmailLength).WithMessage($"Email must be at least {AuthConstants.MinEmailLength} characters long.")
                .MaximumLength(AuthConstants.MaxEmailLength).WithMessage($"Email must be at most {AuthConstants.MaxEmailLength} characters long.")
                .EmailAddress().WithMessage("A valid email address is required.");
            
            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password is required.")
                .MinimumLength(AuthConstants.MinPasswordLength).WithMessage($"Password must be at least {AuthConstants.MinPasswordLength} characters long.")
                .MaximumLength(AuthConstants.MaxPasswordLength).WithMessage($"Password must be at most {AuthConstants.MaxPasswordLength} characters long.");

            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("First name is required.")
                .MinimumLength(AuthConstants.MinFirstNameLength).WithMessage($"First name must be at least {AuthConstants.MinFirstNameLength} characters long.")
                .MaximumLength(AuthConstants.MaxFirstNameLength).WithMessage($"First name must be at most {AuthConstants.MaxFirstNameLength} characters long.");
        }
    }
}
