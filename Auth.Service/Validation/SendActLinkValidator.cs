using Cmas.Services.Auth.Dtos.Request;
using FluentValidation;

namespace Cmas.Services.Auth.Validation
{
    /// <summary>
    /// 
    /// </summary>
    public class SendActLinkValidator : AbstractValidator<SendActLinkRequest>
    {
        public SendActLinkValidator()
        {
            RuleFor(request => request.Login)
                .Must(s => !string.IsNullOrEmpty(s))
                .WithMessage("login cannot be empty");

            RuleFor(request => request.Email)
                .Must(s => !string.IsNullOrEmpty(s))
                .WithMessage("email cannot be empty");
        }
    }
}