namespace Cmas.Services.Auth.Entities
{
    public class JwtToken
    {
        /// <summary>
        /// Subject of the JWT
        /// </summary>
        public string sub;

        /// <summary>
        /// Expiration time on or after which the JWT MUST NOT be accepted for processing.
        /// </summary>
        public long exp;

        /// <summary>
        /// Time at which the JWT was issued.
        /// </summary>
        public long iat;

        /// <summary>
        /// Roles
        /// </summary>
        public string roles;

        /// <summary>
        /// short password  hash
        /// </summary>
        public string sph;
    }
}