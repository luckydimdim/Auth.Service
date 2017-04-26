using Cmas.Services.Auth.Dtos.Request;
using FluentValidation;

namespace Cmas.Services.Auth.Validation
{
    class GetTokenValidator : AbstractValidator<GetTokenRequest>
    {
        public GetTokenValidator()
        {
            RuleFor(request => request.Login)
                .Must(login => !string.IsNullOrEmpty(login))
                .WithMessage("login cannot be empty");

            RuleFor(request => request.Login)
                .Must(login => login.Length <= 256)
                .WithMessage("login max length: 256");

            RuleFor(request => request.Password)
                .Must(password => !string.IsNullOrEmpty(password))
                .WithMessage("password cannot be empty");

            RuleFor(request => request.Password)
                .Must(password => password.Length <= 256)
                .WithMessage("password max length: 256");
        }
    }
}