﻿using System;
using System.Threading.Tasks;
using Nancy;
using System.Threading;
using Cmas.Services.Auth.Dtos.Request;
using Nancy.Validation;
using Nancy.ModelBinding;
using Cmas.Infrastructure.ErrorHandler;

namespace Cmas.Services.Auth
{
    public class AuthModule : NancyModule
    {

        private readonly IServiceProvider _serviceProvider;

        private AuthService authService;

        private AuthService _authService {
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

        #endregion
    }
}