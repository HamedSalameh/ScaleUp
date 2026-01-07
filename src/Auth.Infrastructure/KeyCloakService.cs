using Auth.Domain.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace Auth.Infrastructure
{
    public partial class KeyCloakService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<KeyCloakService> _logger;

        public KeyCloakService(HttpClient httpClient, IConfiguration configuration, ILogger<KeyCloakService> logger)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<string?> SigninAsync(string username, string password, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("Username cannot be null or empty.", nameof(username));
            }
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            }

            try
            {
                var tokenResponse = await ExchangeCredentialsForTokens(username, password, cancellationToken);

                if (tokenResponse == null)
                {
                    _logger.LogWarning("Token response is null for user {Username}.", username);
                    return null;
                }

                var userInfo = ParseJwtToken(tokenResponse.AccessToken);

                if (userInfo == null)
                {
                    _logger.LogWarning("Failed to parse user info from access token for user {Username}.", username);
                    return null;
                }

                _logger.LogInformation("User {Username} signed in successfully.", username);
                return tokenResponse.AccessToken;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request error while signing in user {Username}.", username);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while signing in user {Username}.", username);
                throw;
            }
        }

        /// <summary>
        /// Parses a JWT access token and extracts user information and roles from its claims.
        /// </summary>
        /// <remarks>The method expects the token to contain standard claims such as "sub",
        /// "preferred_username", "email", "given_name", and "family_name". Roles are extracted from the "realm_access"
        /// claim if present. If the token is invalid or missing required claims, the returned <see
        /// cref="UserInfoResponse"/> may contain empty values for those fields.</remarks>
        /// <param name="accessToken">The JWT access token to parse. Must be a valid, non-empty JWT string.</param>
        /// <returns>A <see cref="UserInfoResponse"/> object containing user information and roles extracted from the token, or
        /// <see langword="null"/> if the token cannot be parsed.</returns>
        private UserInfoResponse? ParseJwtToken(string accessToken)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                _logger.LogWarning("Access token is null or empty.");
                return null;
            }

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(accessToken);
            if (jwtToken == null)
            {
                _logger.LogWarning("Failed to parse JWT token.");
                return null;
            }

            var userInfo = new UserInfoResponse
            {
                UserId = jwtToken.Subject,
                UserName = jwtToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value ?? string.Empty,
                Email = jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value ?? string.Empty,
                FirstName = jwtToken.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value ?? string.Empty,
                LastName = jwtToken.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value ?? string.Empty,
            };

            // now extract the roles from the access token

            var realmAccess = jwtToken.Claims.FirstOrDefault(c => c.Type == "realm_access")?.Value;
            if (!string.IsNullOrEmpty(realmAccess))
            {
                try
                {
                    var rolesJson = JsonSerializer.Deserialize<JsonElement>(realmAccess);
                    if (rolesJson.TryGetProperty("roles", out var roles))
                    {
                        userInfo.Roles = roles.EnumerateArray()
                            .Select(r => r.GetString() ?? "")
                            .Where(r => !string.IsNullOrEmpty(r))
                            .ToList();
                    }
                }
                catch (JsonException ex)
                {
                    _logger.LogWarning(ex, "Failed to parse realm roles from JWT");
                }
            }

            return userInfo;
        }

        /// <summary>
        /// Exchanges the specified user credentials for a set of Keycloak authentication tokens.
        /// </summary>
        /// <remarks>This method sends a request to the configured Keycloak token endpoint using the
        /// Resource Owner Password Credentials grant type. If the credentials are invalid or the request fails, the
        /// method returns <see langword="null"/> and logs an error.</remarks>
        /// <param name="username">The username of the user whose credentials are to be exchanged for tokens. Cannot be null or empty.</param>
        /// <param name="password">The password associated with the specified username. Cannot be null or empty.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a <see
        /// cref="KeyCloakTokenResponse"/> with the authentication tokens if the exchange is successful; otherwise, <see
        /// langword="null"/>.</returns>
        private async Task<KeyCloakTokenResponse?> ExchangeCredentialsForTokens(string username, string password, CancellationToken cancellationToken)
        {
            var tokenEndpoint = _configuration["KeyCloak:TokenEndpoint"];
            var clientId = _configuration["KeyCloak:ClientId"];
            var clientSecret = _configuration["KeyCloak:ClientSecret"];

            var tokenRequest = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "client_id", clientId ?? string.Empty },
                { "client_secret", clientSecret ?? string.Empty },
                { "username", username },
                { "password", password }
            };

            var requestContent = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(tokenEndpoint ?? string.Empty, requestContent, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to exchange credentials for tokens. Status Code: {StatusCode}", response.StatusCode);
                return null;
            }
            var responseContent = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<KeyCloakTokenResponse>(responseContent);
            return tokenResponse;
        }
    }
}
