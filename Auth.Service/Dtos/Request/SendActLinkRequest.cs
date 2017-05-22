
namespace Cmas.Services.Auth.Dtos.Request
{
    /// <summary>
    /// Запрос на отправку ссылки активации пользователя
    /// </summary>
    public class SendActLinkRequest
    {
        /// <summary>
        /// Логин пользователя
        /// </summary>
        public string Login;

        /// <summary>
        /// Почта, куда отправляется ссылка
        /// </summary>
        public string Email;
    }
}
