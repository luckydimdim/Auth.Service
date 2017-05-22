using Cmas.Services.Auth.Dtos.Request;
using FluentValidation;

namespace Cmas.Services.Auth.Validation
{
    /// <summary>
    /// Валидация активации пользователя
    /// </summary>
    public class ActivateValidator : AbstractValidator<ActivateRequest>
    {
        public ActivateValidator()
        {
            RuleFor(request => request.Login)
                .Must(s => !string.IsNullOrEmpty(s))
                .WithMessage("login cannot be empty");

            RuleFor(request => request.Password)
                .Must(s => !string.IsNullOrEmpty(s))
                .WithMessage("password cannot be empty");

            RuleFor(request => request.Hash)
                .Must(s => !string.IsNullOrEmpty(s))
                .WithMessage("hash cannot be empty");
        }
    }
}