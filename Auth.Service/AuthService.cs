using AutoMapper;
using System;

namespace Cmas.Services.Auth
{
    public class AuthService
    {
        private readonly IMapper _autoMapper;

        public AuthService(IServiceProvider serviceProvider)
        {
            _autoMapper = (IMapper) serviceProvider.GetService(typeof(IMapper));
        }
    }
}