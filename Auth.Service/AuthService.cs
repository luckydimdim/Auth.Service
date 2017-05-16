using AutoMapper;
using System;
using System.Collections.Generic;
using Jose;
using Microsoft.Extensions.Logging;
using Cmas.BusinessLayers.Users; 
using Cmas.BusinessLayers.Users.Entities;
using System.Threading.Tasks;
using Cmas.Infrastructure.ErrorHandler;
using System.Security.Cryptography;
using System.Text;
using Cmas.Infrastructure.Configuration;
using Cmas.Services.Auth.Entities;
using Nancy;
using MimeKit;
using MailKit.Net.Smtp;
using MailKit.Security;

namespace Cmas.Services.Auth
{
    public class AuthService
    {
        private readonly IMapper _autoMapper;
        private readonly ILogger _logger;
        private readonly UsersBusinessLayer _usersBusinessLayer;
        private readonly CmasConfiguration _cmasConfiguration;

        public AuthService(IServiceProvider serviceProvider, NancyContext ctx)
        {
            _autoMapper = (IMapper) serviceProvider.GetService(typeof(IMapper));
            _cmasConfiguration = serviceProvider.GetConfiguration();

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

            User user = null;
            try
            {
                user = await _usersBusinessLayer.GetUser(login);
            }
            catch (NotFoundErrorException)
            {
                throw new AuthorizationErrorException("Incorrect login or password");
            }

            if (user == null)
            {
                throw new AuthorizationErrorException("Incorrect login or password");
            }

            if (!string.IsNullOrEmpty(user.actHash))
            {
                throw new AuthorizationErrorException("User not activated");
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

            User user = null;
            try
            {
                user = await _usersBusinessLayer.GetUser(payload.sub);
            }
            catch (NotFoundErrorException)
            {
                throw new AuthorizationErrorException("User not found");
            }

            if (!string.IsNullOrEmpty(user.actHash))
            {
                throw new AuthorizationErrorException("User not activated");
            }

            var shortPasswordHash = GetShortPasswordHash(user.PasswordHash);

            if (shortPasswordHash != payload.sph)
            {
                _logger.LogInformation("Incorrect token (password changed)");
                throw new InvalidTokenErrorException();
            }
             
            return CreateToken(user);
        }

        public async Task<bool> ActivateAsync(string login, string password, string hash)
        {
            if (string.IsNullOrEmpty(login))
                throw new ArgumentException("login");

            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("password");

            if (string.IsNullOrEmpty(hash))
                throw new ArgumentException("hash");

            _logger.LogInformation(string.Format("user activating... login = {0}", login));

            User user = null;

            try
            {
                user = await _usersBusinessLayer.GetUser(login);
            }
            catch (NotFoundErrorException)
            {
                _logger.LogInformation("user not found");
                return false;
            }

            if (user.actHash != hash)
            {
                _logger.LogInformation("hashes are different");
                return false;
            }

            if (!PasswordIsSecure(password))
            {
                _logger.LogInformation("password is not secure");
                return false;
            }

            user.PasswordHash = sha256(password, user.Id);
            user.actHash = string.Empty;

            await _usersBusinessLayer.UpdateUser(user);

            return true;
        }

        public async Task SendActivationLinkAsync(string login, string email)
        {

            if (string.IsNullOrEmpty(login))
                throw new ArgumentException("login");

            if (string.IsNullOrEmpty(email))
                throw new ArgumentException("email");

            User user = null;

            try
            {
                user = await _usersBusinessLayer.GetUser(login);
            }
            catch (NotFoundErrorException)
            {
                _logger.LogInformation("user not found");
                return;
            }

            //TODO: вынести в конфиг
            var fromName = "cmas";
            var fromMail = _cmasConfiguration.Smtp.From;
            var smtpHost = _cmasConfiguration.Smtp.Host;
            var smtpPort = _cmasConfiguration.Smtp.Port;
            var smtpLogin = _cmasConfiguration.Smtp.Login;
            var smtpPassword = _cmasConfiguration.Smtp.Password;
            var cmasUrl = _cmasConfiguration.CmasUrl;

            var emailMessage = new MimeMessage();

            string actHash = sha256(Guid.NewGuid().ToString(), login);
            string url = string.Format("{0}/web/index.html#/activation?actHash={1}&login={2}", cmasUrl, actHash, login);

            string message = string.Format("Для активации аккаунта {0} в системе CMAS необходимо перейти по указанной ссылке:\n\n{1}", login, url);
            message += "\n\nДанное письмо создано автоматически, на него не надо отвечать";


            user.actHash = actHash;
            await _usersBusinessLayer.UpdateUser(user);

            _logger.LogInformation(String.Format("Хэш успешно сохранен"));

            emailMessage.From.Add(new MailboxAddress(fromName, fromMail));
            emailMessage.To.Add(new MailboxAddress("", email));
            emailMessage.Subject = "CMAS. Активация аккаунта";
            emailMessage.Body = new TextPart("plain") { Text = message };

            using (var client = new SmtpClient())
            { 
                client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                await client.ConnectAsync(smtpHost, smtpPort, SecureSocketOptions.StartTls).ConfigureAwait(false);
                await client.AuthenticateAsync(smtpLogin, smtpPassword);
                await client.SendAsync(emailMessage).ConfigureAwait(false);
                await client.DisconnectAsync(true).ConfigureAwait(false);
            }

            _logger.LogInformation(String.Format("Ссылка на активацию успешно отправлена"));
        }

        /// <summary>
        ///     Проверка безопасности пароля
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        public static bool PasswordIsSecure(string password)
        {
            var minimumLength = 7;
            var maximumLength = 100;

            var letters = 0;
            var upperCaseLetters = 0;
            var lowerCaseLetters = 0;
            var digits = 0;

            if (String.IsNullOrEmpty(password))
                return false;

            if (password.Length < minimumLength || password.Length > maximumLength)
                return false;

            foreach (var ch in password)
            {
                if (Char.IsLetter(ch))
                {
                    letters++;

                    if (Char.IsLower(ch))
                    {
                        lowerCaseLetters++;
                    }

                    if (Char.IsUpper(ch))
                    {
                        upperCaseLetters++;
                    }
                }
                else if (Char.IsDigit(ch))
                    digits++;
            }

            if (!((letters >= 2 && digits >= 5) || (letters >= 5 && digits >= 2)))
                return false; // Минимальное использование 2 буквы и 5 цифр, или 5 букв и 2 цифры.

            if (lowerCaseLetters == 0 || upperCaseLetters == 0)
                return false; // обязательное использование букв разного регистра

            return true;
        }
    }
}