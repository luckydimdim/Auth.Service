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

        private static string Sha256(string secret, string salt)
        {
            if (string.IsNullOrEmpty(secret))
                throw new ArgumentException("secret");

            if (string.IsNullOrEmpty(salt))
                throw new ArgumentException("salt");

            var str = $"{secret}--{salt}";

            using (var algorithm = SHA256.Create())
            {
                var hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(str), 0, Encoding.UTF8.GetByteCount(str));

                return ByteArrayToString(hash);
            }
        }

        private static string ByteArrayToString(byte[] inputArray)
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

        /// <summary>
        /// Создать токен для указанного пользователя
        /// </summary>
        private string CreateToken(User user)
        {
            if (user == null)
                throw new ArgumentException("user");

            _logger.LogInformation($"creating token for user. Login: {user.Login}");

            var expDate = DateTime.UtcNow.AddHours(1).Ticks;
            var issuedAt = DateTime.UtcNow.Ticks;
            var roles = string.Join(",", user.Roles);

            _logger.LogInformation($"expDate: {expDate} issuedAt: {issuedAt} roles: {roles}");

            var shortPasswordHash = GetShortPasswordHash(user.PasswordHash);

            var payload = new Dictionary<string, object>()
            {
                {"sub", user.Login},
                {"exp", expDate},
                {"iat", issuedAt},
                {"sph", shortPasswordHash},
                {"snm", user.Name},
                {"roles", roles},
            };

            var encryptedResult = JWT.Encode(payload, Consts.secretKey, JwsAlgorithm.HS256);

            _logger.LogInformation($"token created: {encryptedResult}");

            return encryptedResult;
        }

        /// <summary>
        /// Создать токен
        /// </summary>
        /// <returns>токен</returns>
        public async Task<string> CreateTokenAsync(string login, string password)
        {
            if (string.IsNullOrEmpty(login))
                throw new ArgumentException("login");

            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("password");

            login = login.ToLower();

            User user = await _usersBusinessLayer.GetUserByLogin(login);

            if (user == null)
            {
                throw new AuthorizationErrorException("Incorrect login or password");
            }

            if (!string.IsNullOrEmpty(user.actHash) || string.IsNullOrEmpty(user.PasswordHash))
            {
                throw new AuthorizationErrorException("User not activated");
            }

            var passwordHash = Sha256(password, user.Id);

            if (user.PasswordHash != passwordHash)
            {
                throw new AuthorizationErrorException("Incorrect login or password");
            }

            return CreateToken(user);
        }

        /// <summary>
        /// Обновить токен (продлить время действия)
        /// </summary>
        /// <param name="tokenToRefresh">старый токен</param>
        /// <returns>новый токен</returns>
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

            var tokenExpires = DateTime.FromBinary(payload.exp);

            _logger.LogInformation($"tokenExpires: {tokenExpires}");

            if (tokenExpires <= DateTime.UtcNow)
            {
                _logger.LogInformation("Token is expired");
                throw new InvalidTokenErrorException();
            }

            User user = await _usersBusinessLayer.GetUserByLogin(payload.sub);

            if (user == null)
                throw new AuthorizationErrorException("User not found");

            if (!string.IsNullOrEmpty(user.actHash) || string.IsNullOrEmpty(user.PasswordHash))
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

        /// <summary>
        /// Активировать пользователя
        /// </summary>
        /// <param name="login">Логин</param>
        /// <param name="password">Пароль</param>
        /// <param name="hash">Хэш активации</param>
        /// <returns></returns>
        public async Task<bool> ActivateAsync(string login, string password, string hash)
        {
            if (string.IsNullOrEmpty(login))
                throw new ArgumentException("login");

            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("password");

            if (string.IsNullOrEmpty(hash))
                throw new ArgumentException("hash");

            _logger.LogInformation($"user activating. Login = {login} hash = {hash}");

            User user = await _usersBusinessLayer.GetUserByLogin(login);

            if (user == null)
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

            user.PasswordHash = Sha256(password, user.Id);
            user.actHash = string.Empty;

            await _usersBusinessLayer.UpdateUser(user);

            _logger.LogInformation($"user with id {user.Id} activated!");

            return true;
        }

        /// <summary>
        /// Выслать ссылку на активацию пользователя
        /// </summary>
        /// <param name="login">Логин пользователя</param>
        /// <param name="email">Почта, куда высылать ссылку</param>
        /// <returns></returns>
        public async Task SendActivationLinkAsync(string login, string email)
        {
            if (string.IsNullOrEmpty(login))
                throw new ArgumentException("login");

            if (string.IsNullOrEmpty(email))
                throw new ArgumentException("email");

            _logger.LogInformation($"sending activation link. Login: {login} email: {email}");
 
            User user =  await _usersBusinessLayer.GetUserByLogin(login);

            if (user == null)
            {
                _logger.LogInformation("user not found");
                return;
            }

            var fromName = "cmas";
            var fromMail = _cmasConfiguration.Smtp.From;
            var smtpHost = _cmasConfiguration.Smtp.Host;
            var smtpPort = _cmasConfiguration.Smtp.Port;
            var smtpLogin = _cmasConfiguration.Smtp.Login;
            var smtpPassword = _cmasConfiguration.Smtp.Password;
            var cmasUrl = _cmasConfiguration.CmasUrl;

            var emailMessage = new MimeMessage();

            string actHash = Sha256(Guid.NewGuid().ToString(), login);
            string url = $"{cmasUrl}/#/activation?actHash={actHash}&login={login}";

            _logger.LogInformation($"generated url: {url}");

            string message =
                $"Для активации аккаунта {login} в системе CMAS необходимо перейти по указанной ссылке:\n\n{url}";
            message += "\n\nДанное письмо создано автоматически, на него не надо отвечать";

            user.actHash = actHash;
            await _usersBusinessLayer.UpdateUser(user);

            _logger.LogInformation("Хэш успешно сохранен");

            emailMessage.From.Add(new MailboxAddress(fromName, fromMail));
            emailMessage.To.Add(new MailboxAddress("", email));
            emailMessage.Subject = "CMAS. Активация аккаунта";
            emailMessage.Body = new TextPart("plain") {Text = message};

            _logger.LogInformation("Отправка сообщения...");

            using (var client = new SmtpClient())
            {
                client.ServerCertificateValidationCallback = (s, c, h, e) => true;
                await client.ConnectAsync(smtpHost, smtpPort, SecureSocketOptions.StartTls).ConfigureAwait(false);
                await client.AuthenticateAsync(smtpLogin, smtpPassword);
                await client.SendAsync(emailMessage).ConfigureAwait(false);
                await client.DisconnectAsync(true).ConfigureAwait(false);
            }

            _logger.LogInformation("Ссылка на активацию успешно отправлена");
        }

        /// <summary>
        ///     Проверка безопасности пароля
        /// </summary>
        /// <param name="password"></param>
        /// <returns>true, если безопасен</returns>
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