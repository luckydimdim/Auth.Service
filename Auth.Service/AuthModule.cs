using System;
using System.Threading.Tasks;
using Nancy;
using System.Threading;
using Cmas.Services.Auth.Dtos.Request;
using Nancy.Validation;
using Nancy.ModelBinding;
using Cmas.Infrastructure.ErrorHandler;
using Nancy.Responses.Negotiation;
using Cmas.Services.Auth.Dtos.Response;
using Cmas.Infrastructure.Security;

namespace Cmas.Services.Auth
{
    public class AuthModule : NancyModule
    {
        private readonly IServiceProvider _serviceProvider;

        private AuthService authService;

        private AuthService _authService
        {
            get
            {
                if (authService == null)
                    authService = new AuthService(_serviceProvider, Context);

                return authService;
            }
        }


        public AuthModule(IServiceProvider serviceProvider) : base("/auth")
        {
            _serviceProvider = serviceProvider;


            /// <summary>
            /// Получить токен
            /// </summary>
            Post<string>("/create-token", GetTokenHandlerAsync);

            /// <summary>
            /// Обновить токен
            /// </summary>
            Post<string>("/refresh-token", RefreshTokenHandlerAsync);

            /// <summary>
            /// Активировать аккаунт
            /// </summary>
            Post<Negotiator>("/activate", ActivateHandlerAsync);

            /// <summary>
            /// 
            /// </summary>
            Post<CheckPassSecurityResponse>("/password-is-secure", CheckPassSecurityHandlerAsync);

            Post<Negotiator>("/send-activation-link", SendActivationLinkHandlerAsync);
        }

        #region Обработчики

        private async Task<string> GetTokenHandlerAsync(dynamic args, CancellationToken ct)
        {
            GetTokenRequest request = this.Bind();

            var validationResult = this.Validate(request);

            if (!validationResult.IsValid)
            {
                throw new ValidationErrorException(validationResult.FormattedErrors);
            }

            return await _authService.CreateTokenAsync(request.Login, request.Password);
        }

        private async Task<string> RefreshTokenHandlerAsync(dynamic args, CancellationToken ct)
        {
            RefreshTokenRequest request = this.Bind();

            var validationResult = this.Validate(request);

            if (!validationResult.IsValid)
            {
                throw new ValidationErrorException(validationResult.FormattedErrors);
            }

            return await _authService.RefreshTokenAsync(request.Token);
        }

        private async Task<Negotiator> ActivateHandlerAsync(dynamic args, CancellationToken ct)
        {
            ActivateRequest request = this.Bind();

            var validationResult = this.Validate(request);

            if (!validationResult.IsValid)
            {
                throw new ValidationErrorException(validationResult.FormattedErrors);
            }

            var result = await _authService.ActivateAsync(request.Login, request.Password, request.Hash);

            if (result)
                return Negotiate.WithStatusCode(HttpStatusCode.OK);
            else
            {
                throw new GeneralServiceErrorException("Error while activating");
            }
        }

        private async Task<CheckPassSecurityResponse> CheckPassSecurityHandlerAsync(dynamic args, CancellationToken ct)
        {
            CheckPassSecurityRequest request = this.Bind();

            var validationResult = this.Validate(request);

            if (!validationResult.IsValid)
            {
                throw new ValidationErrorException(validationResult.FormattedErrors);
            }

            var result = AuthService.PasswordIsSecure(request.Password);

            if (result)
                return new CheckPassSecurityResponse {Result = true};
            else
            {
                return new CheckPassSecurityResponse {Result = false};
            }
        }

        private async Task<Negotiator> SendActivationLinkHandlerAsync(dynamic args, CancellationToken ct)
        {
            this.RequiresRoles(new[] { Role.Administrator });

            SendActLinkRequest request = this.Bind();

            var validationResult = this.Validate(request);

            if (!validationResult.IsValid)
            {
                throw new ValidationErrorException(validationResult.FormattedErrors);
            }

            await _authService.SendActivationLinkAsync(request.Login, request.Email);
             
            return Negotiate.WithStatusCode(HttpStatusCode.OK);
        }

        #endregion
    }
}