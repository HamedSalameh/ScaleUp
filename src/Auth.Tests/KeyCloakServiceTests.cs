using Auth.Domain.Models;
using Auth.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Moq.Protected;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Auth.Tests
{
    [TestFixture]
    public class KeyCloakServiceTests
    {
        private Mock<HttpMessageHandler> _handlerMock;
        private Mock<IConfiguration> _configMock;
        private Mock<ILogger<KeyCloakService>> _loggerMock;
        private HttpClient _httpClient;
        private KeyCloakService _service;

        [SetUp]
        public void SetUp()
        {
            _handlerMock = new Mock<HttpMessageHandler>();
            _configMock = new Mock<IConfiguration>();
            _loggerMock = new Mock<ILogger<KeyCloakService>>();

            // Setup Configuration values
            _configMock.Setup(x => x["KeyCloak:TokenEndpoint"]).Returns("https://auth.test.com/token");
            _configMock.Setup(x => x["KeyCloak:ClientId"]).Returns("test-client");
            _configMock.Setup(x => x["KeyCloak:ClientSecret"]).Returns("test-secret");

            _httpClient = new HttpClient(_handlerMock.Object);
            _service = new KeyCloakService(_httpClient, _configMock.Object, _loggerMock.Object);
        }

        [TearDown]
        public void TearDown()
        {
            _httpClient?.Dispose();
        }

        #region Constructor Tests

        [Test]
        public void Constructor_WithNullHttpClient_ThrowsArgumentNullException()
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentNullException>(() =>
                new KeyCloakService(null!, _configMock.Object, _loggerMock.Object));

            Assert.That(ex!.ParamName, Is.EqualTo("httpClient"));
        }

        [Test]
        public void Constructor_WithNullConfiguration_ThrowsArgumentNullException()
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentNullException>(() =>
                new KeyCloakService(_httpClient, null!, _loggerMock.Object));

            Assert.That(ex!.ParamName, Is.EqualTo("configuration"));
        }

        [Test]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentNullException>(() =>
                new KeyCloakService(_httpClient, _configMock.Object, null!));

            Assert.That(ex!.ParamName, Is.EqualTo("logger"));
        }

        [Test]
        public void Constructor_WithValidParameters_CreatesInstance()
        {
            // Act
            var service = new KeyCloakService(_httpClient, _configMock.Object, _loggerMock.Object);

            // Assert
            Assert.That(service, Is.Not.Null);
        }

        #endregion

        #region Input Validation Tests

        [Test]
        public void SigninAsync_NullUsername_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
                await _service.SigninAsync(null!, "password", CancellationToken.None));

            Assert.That(ex!.ParamName, Is.EqualTo("username"));
            Assert.That(ex.Message, Does.Contain("Username cannot be null or empty"));
        }

        [Test]
        public void SigninAsync_EmptyUsername_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
                await _service.SigninAsync("", "password", CancellationToken.None));

            Assert.That(ex!.ParamName, Is.EqualTo("username"));
            Assert.That(ex.Message, Does.Contain("Username cannot be null or empty"));
        }

        [Test]
        public void SigninAsync_WhitespaceUsername_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
                await _service.SigninAsync("   ", "password", CancellationToken.None));

            Assert.That(ex!.ParamName, Is.EqualTo("username"));
        }

        [Test]
        public void SigninAsync_NullPassword_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
                await _service.SigninAsync("user", null!, CancellationToken.None));

            Assert.That(ex!.ParamName, Is.EqualTo("password"));
            Assert.That(ex.Message, Does.Contain("Password cannot be null or empty"));
        }

        [Test]
        public void SigninAsync_EmptyPassword_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
                await _service.SigninAsync("user", "", CancellationToken.None));

            Assert.That(ex!.ParamName, Is.EqualTo("password"));
            Assert.That(ex.Message, Does.Contain("Password cannot be null or empty"));
        }

        [Test]
        public void SigninAsync_WhitespacePassword_ThrowsArgumentException()
        {
            // Act & Assert
            var ex = Assert.ThrowsAsync<ArgumentException>(async () =>
                await _service.SigninAsync("user", "   ", CancellationToken.None));

            Assert.That(ex!.ParamName, Is.EqualTo("password"));
        }

        #endregion

        #region Successful Signin Tests

        [Test]
        public async Task SigninAsync_ValidCredentials_ReturnsAccessToken()
        {
            // Arrange
            var username = "john.doe";
            var password = "securePassword";
            var accessToken = GenerateFakeJwt(username, "john.doe@example.com", "John", "Doe");

            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = "refresh-token-123",
                ExpiresIn = 3600,
                TokenType = "Bearer"
            };

            SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

            // Act
            var result = await _service.SigninAsync(username, password, CancellationToken.None);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result, Is.EqualTo(accessToken));
            VerifyLog(LogLevel.Information, $"User {username} signed in successfully.");
        }

        [Test]
        [TestCase("admin", "AdminPass123!")]
        [TestCase("user@example.com", "UserPassword")]
        [TestCase("test.user", "Test@1234")]
        public async Task SigninAsync_VariousValidCredentials_ReturnsAccessToken(string username, string password)
        {
            // Arrange
            var accessToken = GenerateFakeJwt(username, $"{username}@test.com", "Test", "User");

            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = accessToken,
                ExpiresIn = 3600
            };

            SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

            // Act
            var result = await _service.SigninAsync(username, password, CancellationToken.None);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result, Is.EqualTo(accessToken));
        }

        [Test]
        public async Task SigninAsync_TokenWithRoles_ReturnsAccessToken()
        {
            // Arrange
            var username = "admin.user";
            var password = "password";
            var roles = new[] { "admin", "user", "manager" };
            var accessToken = GenerateFakeJwtWithRoles(username, "admin@test.com", "Admin", "User", roles);

            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = accessToken,
                ExpiresIn = 3600
            };

            SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

            // Act
            var result = await _service.SigninAsync(username, password, CancellationToken.None);

            // Assert
            Assert.That(result, Is.Not.Null);
            Assert.That(result, Is.EqualTo(accessToken));
        }

        [Test]
        public async Task SigninAsync_WithCancellationToken_PassesTokenToHttpClient()
        {
            // Arrange
            var username = "test.user";
            var password = "password";
            var accessToken = GenerateFakeJwt(username, "test@test.com", "Test", "User");
            var cts = new CancellationTokenSource();

            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = accessToken,
                ExpiresIn = 3600
            };

            _handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.Is<CancellationToken>(ct => ct == cts.Token))
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(JsonSerializer.Serialize(tokenResponse), Encoding.UTF8, "application/json")
                });

            // Act
            var result = await _service.SigninAsync(username, password, cts.Token);

            // Assert
            Assert.That(result, Is.Not.Null);
        }

        #endregion

        #region Failed Signin Tests

        [Test]
        public async Task SigninAsync_UnauthorizedResponse_ReturnsNull()
        {
            // Arrange
            SetupHttpResponse(HttpStatusCode.Unauthorized, "{\"error\":\"invalid_grant\"}");

            // Act
            var result = await _service.SigninAsync("user", "wrongpass", CancellationToken.None);

            // Assert
            Assert.That(result, Is.Null);
        }

        [Test]
        public async Task SigninAsync_BadRequestResponse_ReturnsNull()
        {
            // Arrange
            SetupHttpResponse(HttpStatusCode.BadRequest, "{\"error\":\"invalid_request\"}");

            // Act
            var result = await _service.SigninAsync("user", "pass", CancellationToken.None);

            // Assert
            Assert.That(result, Is.Null);
        }

        [Test]
        public async Task SigninAsync_NullTokenResponse_ReturnsNull()
        {
            // Arrange
            SetupHttpResponse(HttpStatusCode.OK, "null");

            // Act
            var result = await _service.SigninAsync("user", "pass", CancellationToken.None);

            // Assert
            Assert.That(result, Is.Null);
        }

        [Test]
        public async Task SigninAsync_EmptyAccessToken_ReturnsNull()
        {
            // Arrange
            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = "",
                ExpiresIn = 3600
            };

            SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

            // Act
            var result = await _service.SigninAsync("user", "pass", CancellationToken.None);

            // Assert
            Assert.That(result, Is.Null);
        }

        [Test]
        public void SigninAsync_InvalidJwtFormat_ThrowsException()
        {
            // Arrange
            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = "not-a-valid-jwt-token",
                ExpiresIn = 3600
            };

            SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

            // Act & Assert
            Assert.ThrowsAsync<SecurityTokenMalformedException>(async () =>
                await _service.SigninAsync("user", "pass", CancellationToken.None));
        }

        [Test]
        public void SigninAsync_NetworkError_ThrowsHttpRequestException()
        {
            // Arrange
            _handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new HttpRequestException("Network error"));

            // Act & Assert
            var ex = Assert.ThrowsAsync<HttpRequestException>(async () =>
                await _service.SigninAsync("user", "pass", CancellationToken.None));

            Assert.That(ex!.Message, Does.Contain("Network error"));
        }

        [Test]
        public void SigninAsync_TaskCanceled_ThrowsTaskCanceledException()
        {
            // Arrange
            _handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new TaskCanceledException("Request was canceled"));

            // Act & Assert
            Assert.ThrowsAsync<TaskCanceledException>(async () =>
                await _service.SigninAsync("user", "pass", CancellationToken.None));
        }

        #endregion

        #region Logging Tests

        [Test]
        public async Task SigninAsync_SuccessfulSignin_LogsInformation()
        {
            // Arrange
            var username = "test.user";
            var accessToken = GenerateFakeJwt(username, "test@test.com", "Test", "User");

            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = accessToken,
                ExpiresIn = 3600
            };

            SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

            // Act
            await _service.SigninAsync(username, "password", CancellationToken.None);

            // Assert
            VerifyLog(LogLevel.Information, $"User {username} signed in successfully.");
        }

        [Test]
        public async Task SigninAsync_NullTokenResponse_LogsWarning()
        {
            // Arrange
            var username = "test.user";
            SetupHttpResponse(HttpStatusCode.OK, "null");

            // Act
            await _service.SigninAsync(username, "password", CancellationToken.None);

            // Assert
            VerifyLog(LogLevel.Warning, $"Token response is null for user {username}");
        }

        [Test]
        public async Task SigninAsync_InvalidJwt_LogsWarning()
        {
            // Arrange
            var username = "test.user";
            var tokenResponse = new KeyCloakTokenResponse
            {
                AccessToken = "invalid-jwt",
                ExpiresIn = 3600
            };

            SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

            // Act & Assert
            try
            {
                await _service.SigninAsync(username, "password", CancellationToken.None);
            }
            catch
            {
                // Exception is expected
            }

            VerifyLog(LogLevel.Error, $"An error occurred while signing in user {username}");
        }

        [Test]
        public async Task SigninAsync_HttpException_LogsError()
        {
            // Arrange
            var username = "test.user";
            _handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new HttpRequestException("Connection failed"));

            // Act & Assert
            try
            {
                await _service.SigninAsync(username, "password", CancellationToken.None);
            }
            catch
            {
                // Exception is expected
            }

            VerifyLog(LogLevel.Error, $"An error occurred while signing in user {username}");
        }

        #endregion

        #region Helper Methods

        private void SetupHttpResponse(HttpStatusCode code, string content)
        {
            _handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = code,
                    Content = new StringContent(content, Encoding.UTF8, "application/json")
                });
        }

        private string GenerateFakeJwt(string username, string email, string firstName, string lastName)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("test-secret-key-that-is-long-enough-for-hmac-sha256"));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim("sub", Guid.NewGuid().ToString()),
                new Claim("preferred_username", username),
                new Claim("email", email),
                new Claim("given_name", firstName),
                new Claim("family_name", lastName)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = credentials,
                Issuer = "test-issuer",
                Audience = "test-audience"
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateFakeJwtWithRoles(string username, string email, string firstName, string lastName, string[] roles)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("test-secret-key-that-is-long-enough-for-hmac-sha256"));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var realmAccess = new { roles };
            var claims = new List<Claim>
            {
                new Claim("sub", Guid.NewGuid().ToString()),
                new Claim("preferred_username", username),
                new Claim("email", email),
                new Claim("given_name", firstName),
                new Claim("family_name", lastName),
                new Claim("realm_access", JsonSerializer.Serialize(realmAccess))
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = credentials,
                Issuer = "test-issuer",
                Audience = "test-audience"
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private void VerifyLog(LogLevel level, string messagePart)
        {
            _loggerMock.Verify(
                x => x.Log(
                    level,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains(messagePart)),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
                Times.AtLeastOnce);
        }

        #endregion
    }
}