using System;
using System.Threading.Tasks;
using Nancy;
using System.Threading;

namespace Cmas.Services.Auth
{
    public class AuthModule : NancyModule
    {
        private readonly AuthService _authService;

        public AuthModule(IServiceProvider serviceProvider) : base("/auth")
        {
            _authService = new AuthService(serviceProvider);


            /// <summary>
            /// 
            /// </summary>
            Get<string>("/{id}", ExampleHandlerAsync);
        }

        #region Обработчики

        private async Task<string> ExampleHandlerAsync(dynamic args, CancellationToken ct)
        {
            return string.Empty;
        }

        #endregion
    }
}