using Cmas.Services.Auth.Dtos.Request;
using FluentValidation;

namespace Cmas.Services.Auth.Validation
{
    public class RefreshTokenValidator : AbstractValidator<RefreshTokenRequest>
    {
        public RefreshTokenValidator()
        {
            RuleFor(request => request.Token)
                .Must(token => !string.IsNullOrEmpty(token))
                .WithMessage("token cannot be empty");
        }
    }
}