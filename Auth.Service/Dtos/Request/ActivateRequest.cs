
namespace Cmas.Services.Auth.Dtos.Request
{
    /// <summary>
    /// Запрос на активацию пользователя
    /// </summary>
    public class ActivateRequest
    {
        /// <summary>
        /// Логин пользователя
        /// </summary>
        public string Login;

        /// <summary>
        /// пароль
        /// </summary>
        public string Password;
    
        /// <summary>
        /// Хэш активации
        /// </summary>
        public string Hash;
    }
}
