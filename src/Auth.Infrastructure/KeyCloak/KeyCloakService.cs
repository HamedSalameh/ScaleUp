using Auth.Domain.Models;
using FluentResults;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace Auth.Infrastructure.KeyCloak
{
    public static class ClientScopes
    {
        public const string OpenId = "openid";
        public const string Identity = "scaleup-identity";
        public const string Authorization = "scaleup-authorization";
    }

    public partial class KeyCloakService : IKeyCloakService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<KeyCloakService> _logger;
        private readonly KeycloakOptions _keycloakOptions;
        private readonly JsonSerializerOptions _jsonOptions;

        public KeyCloakService(HttpClient httpClient, IConfiguration configuration, ILogger<KeyCloakService> logger, IOptions<KeycloakOptions> keycloakOptions)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _keycloakOptions = keycloakOptions?.Value ?? throw new ArgumentNullException(nameof(keycloakOptions));

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
        }

        /// <summary>
        /// Authenticates a user with the specified credentials and returns a JWT access token if successful.
        /// </summary>
        /// <param name="username">The username of the user to authenticate. Cannot be null or empty.</param>
        /// <param name="password">The password associated with the specified username. Cannot be null or empty.</param>
        /// <param name="cancellationToken">A cancellation token that can be used to cancel the sign-in operation.</param>
        /// <returns>A result containing the JWT access token if authentication is successful; otherwise, a failed result with
        /// error details.</returns>
        /// <exception cref="InvalidOperationException">Thrown if a network error occurs while contacting the authentication server.</exception>
        public async Task<Result<string>> SigninAsync(string username, string password, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(username))
                return Result.Fail<string>("Username cannot be null or empty.");

            if (string.IsNullOrWhiteSpace(password))
                return Result.Fail<string>("Password cannot be null or empty.");

            try
            {
                var tokenResult = await ExchangeCredentialsForTokens(username, password, cancellationToken);

                if (tokenResult.IsFailed)
                {
                    _logger.LogWarning("Signin failed for user {Username}: {Errors}", username, string.Join(",", tokenResult.Errors.Select(e => e.Message)));
                    return Result.Fail<string>(tokenResult.Errors);
                }

                var token = tokenResult.Value;

                var parseResult = ParseJwtToken(token.AccessToken);

                if (parseResult.IsFailed)
                {
                    _logger.LogWarning("Failed to parse access token for user {Username}: {Errors}", username, string.Join(",", parseResult.Errors.Select(e => e.Message)));
                    return Result.Fail<string>(parseResult.Errors);
                }

                _logger.LogInformation("User {Username} signed in successfully.", username);
                return Result.Ok(token.AccessToken);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request error while signing in user {Username}.", username);
                throw new InvalidOperationException("Network error while contacting Keycloak.", ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while signing in user {Username}.", username);
                throw;
            }
        }

        private Result<UserInfoResponse> ParseJwtToken(string accessToken)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
                return Result.Fail<UserInfoResponse>("Access token is null or empty.");

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(accessToken);

                if (jwtToken == null)
                    return Result.Fail<UserInfoResponse>("Failed to parse JWT token.");

                var userInfo = new UserInfoResponse
                {
                    UserId = jwtToken.Subject ?? string.Empty,
                    UserName = jwtToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value ?? string.Empty,
                    Email = jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value ?? string.Empty,
                    FirstName = jwtToken.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value ?? string.Empty,
                    LastName = jwtToken.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value ?? string.Empty,
                    Roles = new List<string>()
                };

                // Extract realm roles
                var realmAccess = jwtToken.Claims.FirstOrDefault(c => c.Type == "realm_access")?.Value;
                if (!string.IsNullOrEmpty(realmAccess))
                {
                    try
                    {
                        var rolesJson = JsonSerializer.Deserialize<JsonElement>(realmAccess, _jsonOptions);
                        if (rolesJson.TryGetProperty("roles", out var roles))
                        {
                            userInfo.Roles = roles.EnumerateArray()
                                .Select(r => r.GetString() ?? string.Empty)
                                .Where(r => !string.IsNullOrEmpty(r))
                                .ToList();
                        }
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse realm roles from JWT");
                    }
                }

                return Result.Ok(userInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while parsing JWT token");
                return Result.Fail<UserInfoResponse>("Exception during JWT parsing: " + ex.Message);
            }
        }

        private async Task<Result<KeyCloakTokenResponse>> ExchangeCredentialsForTokens(string username, string password, CancellationToken cancellationToken)
        {
            var requestedClientScopes = $"{ClientScopes.OpenId} {ClientScopes.Identity} {ClientScopes.Authorization}";

            try
            {
                var tokenRequest = new Dictionary<string, string>
                {
                    { "grant_type", "password" },
                    { "client_id", _keycloakOptions.ClientId },
                    { "client_secret", _keycloakOptions.ClientSecret },
                    { "username", username },
                    { "password", password },
                    { "scope", requestedClientScopes }
                };

                using var content = new FormUrlEncodedContent(tokenRequest);
                using var response = await _httpClient.PostAsync(_keycloakOptions.TokenEndpoint, content, cancellationToken);

                var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    string errorMsg;
                    try
                    {
                        var errorDict = JsonSerializer.Deserialize<Dictionary<string, string>>(responseContent, _jsonOptions);
                        errorMsg = errorDict != null
                            ? $"{errorDict.GetValueOrDefault("error")}: {errorDict.GetValueOrDefault("error_description")}"
                            : responseContent;
                    }
                    catch
                    {
                        errorMsg = responseContent;
                    }

                    _logger.LogWarning("Keycloak token request failed for user {Username}: {Error}", username, errorMsg);
                    return Result.Fail<KeyCloakTokenResponse>(errorMsg);
                }

                var tokenResponse = JsonSerializer.Deserialize<KeyCloakTokenResponse>(responseContent, _jsonOptions);
                if (tokenResponse == null)
                    return Result.Fail<KeyCloakTokenResponse>("Failed to parse Keycloak token response.");

                return Result.Ok(tokenResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception while exchanging credentials for user {Username}", username);
                throw;
            }
        }
    }
}
