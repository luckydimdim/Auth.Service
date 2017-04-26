using System;
using System.Security.Claims;
using System.Security.Principal;
using Jose;
using Cmas.Services.Auth.Entities;
using Microsoft.Extensions.Logging;
using Cmas.Infrastructure.Security;

namespace Cmas.Services.Auth
{
    public class UserApiMapper : IUserApiMapper
    {
        private readonly ILogger _logger;

        public UserApiMapper(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<UserApiMapper>();
        }

        /// <summary>
        /// Получить 
        /// </summary>
        /// <param name="jwtToken"></param>
        public ClaimsPrincipal GetUserFromAccessToken(string jwtToken)
        {
            if (string.IsNullOrEmpty(jwtToken))
            {
                return null;
            }

            try
            {
                var payload = JWT.Decode<JwtToken>(jwtToken, Consts.secretKey);

                var tokenExpires = DateTime.FromBinary(payload.exp);

                if (tokenExpires <= DateTime.UtcNow)
                {
                    _logger.LogInformation("Token is expired");
                    return null;
                }

                // TODO: Проверять хэш пароля в токене, роли
                var identity = new GenericIdentity(payload.sub);

                var roles = payload.roles.Split(',');

                foreach (var role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role.ToString(), role));
                }

                var principal = new ClaimsPrincipal(identity);

                return principal;
            }
            catch (Exception exc)
            {
                _logger.LogWarning("Incorrect token", exc);
                return null;
            }
        }
    }
}