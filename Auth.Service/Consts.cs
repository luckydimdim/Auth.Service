namespace Cmas.Services.Auth
{
    public static class Consts
    {
        /// <summary>
        /// Секретный ключ для шифрования паролей
        /// </summary>
        public static byte[] secretKey = new byte[]
        {
            164, 60, 194, 0, 161, 189, 10, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 20, 216, 191, 131, 47,
            250, 32, 107, 231, 40, 37, 158, 225, 234
        };
    }
}