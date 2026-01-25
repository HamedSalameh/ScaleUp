using System.ComponentModel.DataAnnotations;

namespace Auth.Infrastructure.KeyCloak
{
    public sealed class KeycloakOptions
    {
        public const string SectionName = "Authentication:Keycloak";

        [Required]
        public string BaseUrl { get; init; } = string.Empty;

        [Required]
        public string Realm { get; init; } = string.Empty;

        [Required]
        public string Authority { get; init; } = string.Empty;

        [Required]
        public string ClientId { get; init; } = string.Empty;

        [Required]
        public string ClientSecret { get; init; } = string.Empty;

        // Admin Client for user management
        [Required]
        public string AdminClientId { get; init; } = string.Empty;

        [Required]
        public string AdminClientSecret { get; init; } = string.Empty;

        public bool RequireHttpsMetadata { get; init; } = true;
        public bool SaveTokens { get; init; } = true;
        public bool ValidateAudience { get; init; } = true;
        [Required]
        public string ValidAudience { get; init; } = string.Empty;

        public string TokenEndpoint => $"{Authority.TrimEnd('/')}/protocol/openid-connect/token";
        public int AccessTokenLifetimeMinutes { get; init; } = 60;
        public int RefreshTokenLifetimeMinutes { get; init; } = 1440;
    }
}
