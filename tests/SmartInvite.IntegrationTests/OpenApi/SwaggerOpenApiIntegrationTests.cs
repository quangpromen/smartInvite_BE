using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.OpenApi;
using SmartInvite.Api.Common;
using SmartInvite.Api.Extensions;
using SmartInvite.Api.OpenApi;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Identity;
using SmartInvite.IntegrationTests.Common;
using Swashbuckle.AspNetCore.SwaggerGen;
using Xunit;

namespace SmartInvite.IntegrationTests.OpenApi;

public class SwaggerOpenApiIntegrationTests : IClassFixture<CustomWebApplicationFactory>
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly CustomWebApplicationFactory _factory;

    public SwaggerOpenApiIntegrationTests(CustomWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task DevelopmentEnvironment_ExposesOpenApiDocument_WithoutLegacyCookieAuthDescriptions()
    {
        var rawJson = await FetchDevelopmentOpenApiRawJsonAsync();
        using var doc = JsonDocument.Parse(rawJson);
        var info = doc.RootElement.GetProperty("info");

        Assert.Equal("SmartInvite API", info.GetProperty("title").GetString());
        Assert.Equal("v1", info.GetProperty("version").GetString());

        var description = info.GetProperty("description").GetString() ?? string.Empty;
        Assert.Contains("BE1", description, StringComparison.Ordinal);
        Assert.Contains("JWT Bearer", description, StringComparison.Ordinal);
        Assert.DoesNotContain("__Host-SmartInvite.Auth", rawJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SmartInviteCookie", rawJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Path=/api/auth", rawJson, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("__Host-SmartInvite.Refresh", rawJson, StringComparison.Ordinal);
        Assert.Contains("Path=/", rawJson, StringComparison.Ordinal);

        await using var devFactory = CreateFactoryForEnvironment("Development");
        using var client = devFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        var duplicateOpenApiResponse = await client.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.NotFound, duplicateOpenApiResponse.StatusCode);
    }

    [Fact]
    public async Task DevelopmentEnvironment_ExposesSwaggerUiAtSwaggerRoute()
    {
        await using var devFactory = CreateFactoryForEnvironment("Development");
        using var noRedirectClient = devFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        var rootUiResponse = await noRedirectClient.GetAsync("/swagger");
        Assert.True(
            rootUiResponse.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or HttpStatusCode.OK,
            $"Unexpected status code for /swagger in Development: {rootUiResponse.StatusCode}");

        var indexUiResponse = await noRedirectClient.GetAsync("/swagger/index.html");
        Assert.Equal(HttpStatusCode.OK, indexUiResponse.StatusCode);
        Assert.Equal("text/html", indexUiResponse.Content.Headers.ContentType?.MediaType);

        var html = await indexUiResponse.Content.ReadAsStringAsync();
        Assert.Contains("SmartInvite API", html, StringComparison.Ordinal);
        Assert.Contains("swagger-ui", html, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task NonDevelopmentEnvironments_DoNotExposeSwaggerUiOrOpenApiJson(string environmentName)
    {
        await using var envFactory = CreateFactoryForEnvironment(environmentName);
        using var client = envFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        var swaggerRootResponse = await client.GetAsync("/swagger");
        var swaggerIndexResponse = await client.GetAsync("/swagger/index.html");
        var swaggerJsonResponse = await client.GetAsync("/swagger/v1/swagger.json");
        var openApiJsonResponse = await client.GetAsync("/openapi/v1.json");

        Assert.Equal(HttpStatusCode.NotFound, swaggerRootResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, swaggerIndexResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, swaggerJsonResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, openApiJsonResponse.StatusCode);
    }

    [Fact]
    public async Task OpenApiDocument_ContainsExactNineBe1JwtEndpoints_AndNoBe2OrLegacyEndpoints()
    {
        using var doc = await FetchDevelopmentOpenApiDocumentAsync();
        var paths = doc.RootElement.GetProperty("paths");

        var actualOperations = new List<string>();
        foreach (var pathProp in paths.EnumerateObject())
        {
            foreach (var methodProp in pathProp.Value.EnumerateObject())
            {
                actualOperations.Add($"{methodProp.Name.ToUpperInvariant()} {pathProp.Name}");
            }
        }

        actualOperations.Sort(StringComparer.Ordinal);

        var expectedOperations = new[]
        {
            "GET /api/auth/csrf",
            "GET /api/auth/me",
            "POST /api/admin/hosts",
            "POST /api/admin/hosts/{hostId}/lock",
            "POST /api/admin/hosts/{hostId}/unlock",
            "POST /api/auth/login",
            "POST /api/auth/logout",
            "POST /api/auth/logout-all",
            "POST /api/auth/refresh"
        };

        Assert.Equal(expectedOperations, actualOperations);

        var forbiddenRouteTokens = new[]
        {
            "event",
            "card",
            "guest",
            "invitation",
            "rsvp",
            "check-in",
            "checkin",
            "dashboard",
            "analytics",
            "/status",
            "/internal"
        };

        foreach (var operation in actualOperations)
        {
            foreach (var forbiddenToken in forbiddenRouteTokens)
            {
                Assert.DoesNotContain(forbiddenToken, operation, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public async Task OpenApiDocument_DefinesHttpBearerJwtScheme_AndAppliesAccurateEndpointAuthorization()
    {
        using var doc = await FetchDevelopmentOpenApiDocumentAsync();
        var root = doc.RootElement;

        Assert.False(
            root.TryGetProperty("security", out var globalSecurity) && globalSecurity.GetArrayLength() > 0,
            "Root OpenAPI document must not impose a non-empty global security requirement on anonymous endpoints.");

        var securitySchemes = root
            .GetProperty("components")
            .GetProperty("securitySchemes");

        var schemeNames = securitySchemes.EnumerateObject().Select(p => p.Name).ToArray();
        Assert.Equal([OpenApiExtensions.BearerSecuritySchemeName], schemeNames);

        var bearerScheme = securitySchemes.GetProperty(OpenApiExtensions.BearerSecuritySchemeName);
        Assert.Equal("http", bearerScheme.GetProperty("type").GetString());
        Assert.Equal("bearer", bearerScheme.GetProperty("scheme").GetString());
        Assert.Equal("JWT", bearerScheme.GetProperty("bearerFormat").GetString());

        var schemeDescription = bearerScheme.GetProperty("description").GetString() ?? string.Empty;
        Assert.Contains("accessToken", schemeDescription, StringComparison.Ordinal);

        var paths = root.GetProperty("paths");

        // Anonymous endpoints: csrf, login, refresh, logout (idempotent refresh cookie revocation)
        foreach (var (anonPath, method) in new[]
        {
            ("/api/auth/csrf", "get"),
            ("/api/auth/login", "post"),
            ("/api/auth/refresh", "post"),
            ("/api/auth/logout", "post")
        })
        {
            var anonOp = paths.GetProperty(anonPath).GetProperty(method);
            AssertHasNoBearerSecurityRequirement(anonOp);
            Assert.Contains("Anonymous", anonOp.GetProperty("description").GetString() ?? string.Empty, StringComparison.Ordinal);
        }

        // Bearer Authenticated endpoints: me, logout-all
        foreach (var (authPath, method) in new[]
        {
            ("/api/auth/me", "get"),
            ("/api/auth/logout-all", "post")
        })
        {
            var authOp = paths.GetProperty(authPath).GetProperty(method);
            AssertRequiresBearerScheme(authOp);
            Assert.Contains("Authenticated", authOp.GetProperty("description").GetString() ?? string.Empty, StringComparison.Ordinal);
        }

        // ADMIN only Bearer endpoints
        foreach (var adminPath in new[]
        {
            "/api/admin/hosts",
            "/api/admin/hosts/{hostId}/lock",
            "/api/admin/hosts/{hostId}/unlock"
        })
        {
            var adminPost = paths.GetProperty(adminPath).GetProperty("post");
            AssertRequiresBearerScheme(adminPost);

            var adminDesc = adminPost.GetProperty("description").GetString() ?? string.Empty;
            var adminSummary = adminPost.GetProperty("summary").GetString() ?? string.Empty;
            Assert.Contains("ADMIN only", $"{adminSummary} {adminDesc}", StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task OpenApiDocument_RequiresCsrfHeaderStrictlyOnCookieBasedEndpoints_AndOmitsItOnBearerAndGetEndpoints()
    {
        using var doc = await FetchDevelopmentOpenApiDocumentAsync();
        var paths = doc.RootElement.GetProperty("paths");

        var cookieCsrfPostPaths = new[]
        {
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/logout"
        };

        foreach (var postPath in cookieCsrfPostPaths)
        {
            var postOp = paths.GetProperty(postPath).GetProperty("post");
            Assert.True(postOp.TryGetProperty("parameters", out var parameters), $"Expected parameters on POST {postPath}");

            var csrfMatches = parameters.EnumerateArray()
                .Where(p =>
                    string.Equals(p.GetProperty("name").GetString(), SecurityCookieConstants.CsrfHeaderName, StringComparison.Ordinal) &&
                    string.Equals(p.GetProperty("in").GetString(), "header", StringComparison.Ordinal))
                .ToArray();

            var csrfParam = Assert.Single(csrfMatches);
            Assert.True(csrfParam.GetProperty("required").GetBoolean());
            Assert.Equal("string", csrfParam.GetProperty("schema").GetProperty("type").GetString());
            Assert.False(csrfParam.TryGetProperty("example", out _));
            Assert.False(csrfParam.TryGetProperty("examples", out _));
        }

        var nonCsrfOperations = new[]
        {
            ("/api/auth/csrf", "get"),
            ("/api/auth/me", "get"),
            ("/api/auth/logout-all", "post"),
            ("/api/admin/hosts", "post"),
            ("/api/admin/hosts/{hostId}/lock", "post"),
            ("/api/admin/hosts/{hostId}/unlock", "post")
        };

        foreach (var (nonCsrfPath, method) in nonCsrfOperations)
        {
            var op = paths.GetProperty(nonCsrfPath).GetProperty(method);
            if (op.TryGetProperty("parameters", out var parameters))
            {
                Assert.DoesNotContain(parameters.EnumerateArray(), p =>
                    string.Equals(p.GetProperty("name").GetString(), SecurityCookieConstants.CsrfHeaderName, StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    [Fact]
    public async Task OpenApiDocument_SchemasAndResponseCodesMatchJwtImplementation_WithoutExposingRefreshTokenOrSecrets()
    {
        var rawJson = await FetchDevelopmentOpenApiRawJsonAsync();
        using var doc = JsonDocument.Parse(rawJson);
        var root = doc.RootElement;
        var schemas = root.GetProperty("components").GetProperty("schemas");

        AssertSchemaPropertiesEqual(schemas, "LoginRequest", ["email", "password"]);
        AssertSchemaPropertiesEqual(schemas, "LoginResponseDto", ["accessToken", "expiresInSeconds", "tokenType", "user"]);
        AssertSchemaPropertiesEqual(schemas, "RefreshResponseDto", ["accessToken", "expiresInSeconds", "tokenType"]);
        AssertSchemaPropertiesEqual(schemas, "CreateHostRequest", ["displayName", "email", "initialPassword"]);
        AssertSchemaPropertiesEqual(schemas, "AuthenticatedUserDto", ["displayName", "email", "id", "lastLoginAt", "roles"]);
        AssertSchemaPropertiesEqual(schemas, "HostSummaryDto", ["createdAt", "displayName", "email", "id", "isLocked", "lastLoginAt"]);

        Assert.False(schemas.GetProperty("LoginRequest").GetProperty("properties").GetProperty("password").TryGetProperty("example", out _));
        Assert.False(schemas.GetProperty("LoginResponseDto").GetProperty("properties").GetProperty("accessToken").TryGetProperty("example", out _));
        Assert.False(schemas.GetProperty("RefreshResponseDto").GetProperty("properties").GetProperty("accessToken").TryGetProperty("example", out _));
        Assert.False(schemas.GetProperty("CreateHostRequest").GetProperty("properties").GetProperty("initialPassword").TryGetProperty("example", out _));
        Assert.DoesNotContain(CustomWebApplicationFactory.TestJwtSigningKey, rawJson, StringComparison.Ordinal);

        var forbiddenSchemaPropertyNames = new[]
        {
            "refreshToken",
            "tokenHash",
            "signingKey",
            "passwordHash",
            "securityStamp",
            "concurrencyStamp",
            "accessFailedCount",
            "lockoutEnd",
            "lockoutEnabled",
            "emailConfirmed",
            "phoneNumber",
            "phoneNumberConfirmed",
            "organizationName",
            "accountStatus",
            "status",
            "rowVersion",
            "updatedAt",
            "fullName",
            "hostProfile",
            "connectionString",
            "bootstrapPassword"
        };

        foreach (var schemaProp in schemas.EnumerateObject())
        {
            Assert.DoesNotContain("ApplicationUser", schemaProp.Name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("IdentityUser", schemaProp.Name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("RefreshToken", schemaProp.Name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("JwtOptions", schemaProp.Name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("BootstrapAdmin", schemaProp.Name, StringComparison.OrdinalIgnoreCase);

            if (!schemaProp.Value.TryGetProperty("properties", out var propsObj))
            {
                continue;
            }

            var propNames = propsObj.EnumerateObject().Select(p => p.Name).ToArray();
            foreach (var forbidden in forbiddenSchemaPropertyNames)
            {
                Assert.DoesNotContain(propNames, name =>
                    string.Equals(name, forbidden, StringComparison.OrdinalIgnoreCase));
            }
        }

        var paths = root.GetProperty("paths");
        AssertEndpointResponseCodesEqual(paths, "/api/auth/csrf", "get", ["200", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/auth/login", "post", ["200", "400", "401", "409", "429", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/auth/refresh", "post", ["200", "400", "401", "429", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/auth/logout", "post", ["200", "400", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/auth/logout-all", "post", ["200", "401", "409", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/auth/me", "get", ["200", "401", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/admin/hosts", "post", ["201", "400", "401", "403", "409", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/admin/hosts/{hostId}/lock", "post", ["200", "400", "401", "403", "404", "409", "500"]);
        AssertEndpointResponseCodesEqual(paths, "/api/admin/hosts/{hostId}/unlock", "post", ["200", "400", "401", "403", "404", "409", "500"]);
    }

    [Fact]
    public async Task SwaggerInDevelopment_DoesNotBypassCsrfOnCookieEndpoints_AndEnforcesBearerAndRoleRules()
    {
        await using var devFactory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IAccessTokenStateValidator>();
                services.AddScoped<IAccessTokenStateValidator, StubSwaggerTokenValidator>();
            });
        });

        using var anonymousClient = new TestSessionClient(devFactory, "198.51.100.120");

        // 1. Referer /swagger must NOT bypass CSRF on login/refresh/logout
        foreach (var cookiePath in new[]
        {
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/logout"
        })
        {
            var response = await anonymousClient.SendAsync(
                HttpMethod.Post,
                cookiePath,
                jsonBody: new { },
                configure: req => req.Headers.Referrer = new Uri("https://localhost/swagger/index.html"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(ErrorCodes.CsrfValidationFailed, (await ReadErrorEnvelopeAsync(response)).Error.Code);
        }

        // 2. Anonymous calls from Swagger UI Referer to Bearer endpoints return 401
        var hostId = Guid.NewGuid();
        foreach (var (method, protectedPath) in new[]
        {
            (HttpMethod.Get, "/api/auth/me"),
            (HttpMethod.Post, "/api/auth/logout-all"),
            (HttpMethod.Post, "/api/admin/hosts"),
            (HttpMethod.Post, $"/api/admin/hosts/{hostId}/lock"),
            (HttpMethod.Post, $"/api/admin/hosts/{hostId}/unlock")
        })
        {
            var unauthResponse = await anonymousClient.SendAsync(
                method,
                protectedPath,
                configure: req => req.Headers.Referrer = new Uri("https://localhost/swagger/index.html"));

            Assert.Equal(HttpStatusCode.Unauthorized, unauthResponse.StatusCode);
            Assert.Equal(ErrorCodes.AuthenticationRequired, (await ReadErrorEnvelopeAsync(unauthResponse)).Error.Code);
        }

        // 3. HOST Bearer token calling Admin endpoint from Swagger UI Referer gets 403 Forbidden (without needing CSRF)
        var tokenService = devFactory.Services.GetRequiredService<IAccessTokenService>();
        var hostJwt = tokenService.CreateAccessToken(
            new AccessTokenSubject(Guid.NewGuid(), "host@example.invalid", "Host", [RoleNames.Host], "STAMP-HOST"),
            DateTimeOffset.UtcNow).AccessToken;

        using var hostClient = new TestSessionClient(devFactory, "198.51.100.122")
        {
            AccessToken = hostJwt
        };

        var forbiddenResponse = await hostClient.SendAsync(
            HttpMethod.Post,
            "/api/admin/hosts",
            new
            {
                email = "host2@example.invalid",
                displayName = "Host Two",
                initialPassword = $"Host#{Guid.NewGuid():N}Aa1!"
            },
            configure: req => req.Headers.Referrer = new Uri("https://localhost/swagger/index.html"));

        Assert.Equal(HttpStatusCode.Forbidden, forbiddenResponse.StatusCode);
    }

    [Fact]
    public void OperationFilters_HandleBearerAuthorizationAndMetadataBasedCsrfDeterministically()
    {
        var authFilter = new AuthorizationOperationFilter();
        var csrfFilter = new CsrfHeaderOperationFilter();
        var openApiDocument = new OpenApiDocument();

        // 1. AllowAnonymous + RequireSmartInviteCsrfMetadata -> Anonymous + single X-CSRF-TOKEN header
        var anonCookiePostContext = CreateOperationFilterContext(
            "POST",
            [new AuthorizeAttribute(AuthorizationPolicies.AdminOnly), new AllowAnonymousAttribute(), new RequireSmartInviteCsrfMetadata()],
            openApiDocument);
        var anonCookiePostOp = new OpenApiOperation();

        authFilter.Apply(anonCookiePostOp, anonCookiePostContext);
        csrfFilter.Apply(anonCookiePostOp, anonCookiePostContext);
        csrfFilter.Apply(anonCookiePostOp, anonCookiePostContext);

        Assert.True(anonCookiePostOp.Security is null || anonCookiePostOp.Security.Count == 0);
        Assert.Contains("Anonymous", anonCookiePostOp.Description ?? string.Empty, StringComparison.Ordinal);
        var singleCsrf = Assert.Single(anonCookiePostOp.Parameters!);
        Assert.Equal(SecurityCookieConstants.CsrfHeaderName, singleCsrf.Name);

        // 2. AdminOnly Bearer POST (without RequireSmartInviteCsrfMetadata) -> Bearer scheme + NO X-CSRF-TOKEN header
        var adminPostContext = CreateOperationFilterContext(
            "POST",
            [new AuthorizeAttribute(AuthorizationPolicies.AdminOnly)],
            openApiDocument);
        var adminPostOp = new OpenApiOperation();

        authFilter.Apply(adminPostOp, adminPostContext);
        csrfFilter.Apply(adminPostOp, adminPostContext);

        Assert.NotNull(adminPostOp.Security);
        Assert.Single(adminPostOp.Security!);
        Assert.Contains("ADMIN only", adminPostOp.Description ?? string.Empty, StringComparison.Ordinal);
        Assert.True(adminPostOp.Parameters is null || adminPostOp.Parameters.Count == 0);
    }

    private WebApplicationFactory<Program> CreateFactoryForEnvironment(string environmentName) =>
        _factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(environmentName);
        });

    private async Task<string> FetchDevelopmentOpenApiRawJsonAsync()
    {
        await using var devFactory = CreateFactoryForEnvironment("Development");
        using var client = devFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/swagger/v1/swagger.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync();
    }

    private async Task<JsonDocument> FetchDevelopmentOpenApiDocumentAsync()
    {
        var rawJson = await FetchDevelopmentOpenApiRawJsonAsync();
        return JsonDocument.Parse(rawJson);
    }

    private static void AssertHasNoBearerSecurityRequirement(JsonElement operation)
    {
        if (!operation.TryGetProperty("security", out var securityElement))
        {
            return;
        }

        Assert.Equal(0, securityElement.GetArrayLength());
    }

    private static void AssertRequiresBearerScheme(JsonElement operation)
    {
        Assert.True(operation.TryGetProperty("security", out var securityElement), "Expected security array on protected operation.");
        Assert.True(securityElement.GetArrayLength() > 0, "Expected non-empty security requirement on protected operation.");

        var hasBearerScheme = securityElement.EnumerateArray()
            .Any(req => req.TryGetProperty(OpenApiExtensions.BearerSecuritySchemeName, out _));

        Assert.True(hasBearerScheme, $"Expected {OpenApiExtensions.BearerSecuritySchemeName} security requirement.");
    }

    private static void AssertSchemaPropertiesEqual(JsonElement schemas, string schemaName, string[] expectedProperties)
    {
        Assert.True(schemas.TryGetProperty(schemaName, out var schema), $"Missing expected schema '{schemaName}'.");
        var actualProperties = schema
            .GetProperty("properties")
            .EnumerateObject()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(expectedProperties, actualProperties);
    }

    private static void AssertEndpointResponseCodesEqual(
        JsonElement paths,
        string path,
        string method,
        string[] expectedStatusCodes)
    {
        var responses = paths
            .GetProperty(path)
            .GetProperty(method)
            .GetProperty("responses");

        var actualCodes = responses
            .EnumerateObject()
            .Select(r => r.Name)
            .OrderBy(c => c, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(expectedStatusCodes, actualCodes);
    }

    private static async Task<ErrorEnvelope> ReadErrorEnvelopeAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        var envelope = JsonSerializer.Deserialize<ErrorEnvelope>(body, JsonOptions);
        Assert.NotNull(envelope);
        Assert.NotNull(envelope.Error);
        return envelope;
    }

    private static OperationFilterContext CreateOperationFilterContext(
        string httpMethod,
        IList<object> endpointMetadata,
        OpenApiDocument document)
    {
        var apiDescription = new ApiDescription
        {
            HttpMethod = httpMethod,
            RelativePath = "api/test",
            ActionDescriptor = new ActionDescriptor
            {
                EndpointMetadata = endpointMetadata
            }
        };

        var schemaGenerator = new SchemaGenerator(
            new SchemaGeneratorOptions(),
            new JsonSerializerDataContractResolver(new JsonSerializerOptions()));

        return new OperationFilterContext(
            apiDescription,
            schemaGenerator,
            new SchemaRepository(),
            document,
            typeof(SwaggerOpenApiIntegrationTests).GetMethod(nameof(OperationFilters_HandleBearerAuthorizationAndMetadataBasedCsrfDeterministically))!);
    }

    private sealed class StubSwaggerTokenValidator : IAccessTokenStateValidator
    {
        public Task<bool> IsPrincipalActiveAsync(ClaimsPrincipal? principal, CancellationToken cancellationToken = default) =>
            Task.FromResult(principal?.Identity?.IsAuthenticated == true);
    }
}
