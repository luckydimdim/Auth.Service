using AutoMapper;
using System;
using System.Collections.Generic;
using Jose;
using Microsoft.Extensions.Logging;
using Cmas.BusinessLayers.Users;
using Cmas.Infrastructure.Domain.Commands;
using Cmas.Infrastructure.Domain.Queries;
using Cmas.BusinessLayers.Users.Entities;
using System.Threading.Tasks;
using Cmas.Infrastructure.ErrorHandler;
using System.Security.Cryptography;
using System.Text;
using Cmas.Services.Auth.Entities;
using Nancy;

namespace Cmas.Services.Auth
{
    public class AuthService
    {
        private readonly IMapper _autoMapper;
        private readonly ILogger _logger;
        private readonly UsersBusinessLayer _usersBusinessLayer;

        public AuthService(IServiceProvider serviceProvider, NancyContext ctx)
        {
            _autoMapper = (IMapper) serviceProvider.GetService(typeof(IMapper));
            var loggerFactory = (ILoggerFactory) serviceProvider.GetService(typeof(ILoggerFactory));
             
            _usersBusinessLayer = new UsersBusinessLayer(serviceProvider, ctx.CurrentUser);


            _logger = loggerFactory.CreateLogger<AuthService>();
        }

        private static string sha256(string password, string salt)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("password");

            if (string.IsNullOrEmpty(salt))
                throw new ArgumentException("salt");

            var str = string.Format("{0}--{1}", password, salt);

            using (var algorithm = SHA256.Create())
            {
                var hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(str), 0, Encoding.UTF8.GetByteCount(str));

                return byteArrayToString(hash);
            }
        }

        public static string byteArrayToString(byte[] inputArray)
        {
            StringBuilder output = new StringBuilder("");
            for (int i = 0; i < inputArray.Length; i++)
            {
                output.Append(inputArray[i].ToString("x2"));
            }
            return output.ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="passwordHash"></param>
        private string GetShortPasswordHash(string passwordHash)
        {
            return passwordHash.Substring(0, 10);
        }

        private string CreateToken(User user)
        {
            if (user == null)
                throw new ArgumentException("user");

            _logger.LogInformation(String.Format("creating token... login: {0}", user.Login));

            var expDate = DateTime.UtcNow.AddHours(1).Ticks;
            var issuedAt = DateTime.UtcNow.Ticks;

            var shortPasswordHash = GetShortPasswordHash(user.PasswordHash);

            var payload = new Dictionary<string, object>()
            {
                {"sub", user.Login},
                {"exp", expDate},
                {"iat", issuedAt},
                {"sph", shortPasswordHash},
                {"snm", user.Name},
                {"roles", string.Join(",", user.Roles)},
            };

            var encryptedResult = JWT.Encode(payload, Consts.secretKey, JwsAlgorithm.HS256);
            var uncryptedResult = JWT.Encode(payload, Consts.secretKey, JwsAlgorithm.none);

            _logger.LogInformation(String.Format("token: {0} / {1}", encryptedResult, uncryptedResult));

            return encryptedResult;
        }

        public async Task<string> CreateTokenAsync(string login, string password)
        {
            if (string.IsNullOrEmpty(login))
                throw new ArgumentException("login");

            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("password");

            login = login.ToLower();

            User user = await _usersBusinessLayer.GetUser(login);

            if (user == null)
            {
                throw new AuthorizationErrorException("Incorrect login or password");
            }

            var passwordHash = sha256(password, user.Id);

            if (user.PasswordHash != passwordHash)
            {
                throw new AuthorizationErrorException("Incorrect login or password");
            }

            return CreateToken(user);
        }

        public async Task<string> RefreshTokenAsync(string tokenToRefresh)
        {
            if (string.IsNullOrEmpty(tokenToRefresh))
                throw new ArgumentException("tokenToRefresh");

            JwtToken payload = null;

            try
            {
                payload = JWT.Decode<JwtToken>(tokenToRefresh, Consts.secretKey);
            }
            catch (Exception exc)
            {
                _logger.LogInformation("Incorrect token", exc);
                throw new InvalidTokenErrorException();
            }

            User user = await _usersBusinessLayer.GetUser(payload.sub);

            var shortPasswordHash = GetShortPasswordHash(user.PasswordHash);

            if (shortPasswordHash != payload.sph)
            {
                _logger.LogInformation("Incorrect token (password changed)");
                throw new InvalidTokenErrorException();
            }

            if (user == null)
            {
                throw new AuthorizationErrorException("User not found");
            }

            return CreateToken(user);
        }
    }
}