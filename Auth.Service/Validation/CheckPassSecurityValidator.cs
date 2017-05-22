using Cmas.Services.Auth.Dtos.Request;
using FluentValidation;

namespace Cmas.Services.Auth.Validation
{
    /// <summary>
    /// Валидация запроса на проверку безопасности пароля
    /// </summary>
    public class CheckPassSecurityValidator : AbstractValidator<CheckPassSecurityRequest>
    {
        public CheckPassSecurityValidator()
        {
            RuleFor(request => request.Password)
                .Must(s => !string.IsNullOrEmpty(s))
                .WithMessage("password cannot be empty");
        }
    }
}