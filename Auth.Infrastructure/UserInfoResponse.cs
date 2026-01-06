namespace Auth.Infrastructure
{
    public partial class KeyCloakService
    {
        /// <summary>
        /// Holds the response from Keycloak token endpoint.
        /// </summary>
        private class UserInfoResponse
        {
            public string UserId { get; set; } = string.Empty;
            public string UserName { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
            public string FirstName { get; set; } = string.Empty;
            public string LastName { get; set; } = string.Empty;
            public List<string> Roles { get; set; } = new List<string>();
        }
    }
}
