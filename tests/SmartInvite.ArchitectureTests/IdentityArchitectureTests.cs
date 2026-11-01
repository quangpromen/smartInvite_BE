using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using NetArchTest.Rules;
using SmartInvite.Application.Auth;
using SmartInvite.Application.Security;
using SmartInvite.Infrastructure.Identity;
using SmartInvite.Infrastructure.Persistence;
using Xunit;

namespace SmartInvite.ArchitectureTests;

public class IdentityArchitectureTests
{
    [Fact]
    public void Domain_ShouldNotDependOn_Jwt_AspNetCore_Or_EntityFrameworkCore()
    {
        var domainAssembly = Domain.AssemblyReference.Assembly;

        var result = Types.InAssembly(domainAssembly)
            .ShouldNot()
            .HaveDependencyOnAny(
                "Microsoft.AspNetCore",
                "Microsoft.EntityFrameworkCore",
                "Microsoft.IdentityModel",
                "System.IdentityModel")
            .GetResult();

        Assert.True(result.IsSuccessful, "Domain không được phụ thuộc vào JWT, Microsoft.AspNetCore.* hoặc EF Core.");

        var referencedNames = domainAssembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(referencedNames, name =>
            name.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("Microsoft.IdentityModel", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("System.IdentityModel", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Application_ShouldNotDependOn_JwtBearer_AspNetCore_EntityFrameworkCore_Or_Swagger()
    {
        var applicationAssembly = Application.AssemblyReference.Assembly;

        var result = Types.InAssembly(applicationAssembly)
            .ShouldNot()
            .HaveDependencyOnAny(
                "Microsoft.AspNetCore",
                "Microsoft.EntityFrameworkCore",
                "Microsoft.IdentityModel",
                "System.IdentityModel",
                "Swashbuckle",
                "Microsoft.OpenApi")
            .GetResult();

        Assert.True(result.IsSuccessful, "Application không được phụ thuộc vào JwtBearer, IdentityModel, AspNetCore, EF Core hoặc Swagger.");

        var referencedNames = applicationAssembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(referencedNames, name =>
            name.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("Microsoft.IdentityModel", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("System.IdentityModel", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("Swashbuckle", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("Microsoft.OpenApi", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ApiEndpoints_ShouldNotReference_DbContext_RefreshTokenEntity_Or_IdentityImplementationDirectly()
    {
        var result = Types.InAssembly(typeof(Program).Assembly)
            .That()
            .ResideInNamespace("SmartInvite.Api.Endpoints")
            .ShouldNot()
            .HaveDependencyOnAny(
                typeof(ApplicationDbContext).FullName!,
                typeof(ApplicationUser).FullName!,
                typeof(RefreshToken).FullName!,
                "Microsoft.EntityFrameworkCore",
                "Microsoft.AspNetCore.Identity")
            .GetResult();

        Assert.True(result.IsSuccessful, "API endpoints không được tham chiếu trực tiếp DbContext, RefreshToken entity hoặc Identity implementation.");
    }

    [Fact]
    public void IdentityAndJwtImplementations_ShouldExistIn_Infrastructure_Only()
    {
        var allSolutionAssemblies = new[]
        {
            Domain.AssemblyReference.Assembly,
            Application.AssemblyReference.Assembly,
            Infrastructure.AssemblyReference.Assembly,
            typeof(Program).Assembly
        };

        var identityUserSubclasses = allSolutionAssemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => !t.IsAbstract && typeof(IdentityUser<Guid>).IsAssignableFrom(t))
            .ToArray();

        Assert.Single(identityUserSubclasses);
        Assert.Equal(typeof(ApplicationUser), identityUserSubclasses[0]);
        Assert.Equal("SmartInvite.Infrastructure.Identity", identityUserSubclasses[0].Namespace);

        var identityDbContextSubclasses = allSolutionAssemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => !t.IsAbstract && typeof(IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>).IsAssignableFrom(t))
            .ToArray();

        Assert.Single(identityDbContextSubclasses);
        Assert.Equal(typeof(ApplicationDbContext), identityDbContextSubclasses[0]);
        Assert.Equal("SmartInvite.Infrastructure.Persistence", identityDbContextSubclasses[0].Namespace);

        var accessTokenImplementations = allSolutionAssemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => t is { IsClass: true, IsAbstract: false } && typeof(IAccessTokenService).IsAssignableFrom(t))
            .ToArray();

        Assert.Single(accessTokenImplementations);
        Assert.Equal(typeof(JwtAccessTokenService), accessTokenImplementations[0]);
        Assert.Equal(Infrastructure.AssemblyReference.Assembly, accessTokenImplementations[0].Assembly);

        var refreshTokenImplementations = allSolutionAssemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => t is { IsClass: true, IsAbstract: false } && typeof(IRefreshTokenService).IsAssignableFrom(t))
            .ToArray();

        Assert.Single(refreshTokenImplementations);
        Assert.Equal(typeof(RefreshTokenService), refreshTokenImplementations[0]);
        Assert.Equal(Infrastructure.AssemblyReference.Assembly, refreshTokenImplementations[0].Assembly);
    }

    [Fact]
    public void Solution_ShouldHaveNoCookieAccessAuthenticationRegistration_OrLegacyAuthCookieConstant()
    {
        var infraCheck = Types.InAssembly(Infrastructure.AssemblyReference.Assembly)
            .ShouldNot()
            .HaveDependencyOn("Microsoft.AspNetCore.Authentication.Cookies")
            .GetResult();

        Assert.True(infraCheck.IsSuccessful, "Infrastructure không được đăng ký CookieAuthentication cho access authentication.");

        var apiCheck = Types.InAssembly(typeof(Program).Assembly)
            .ShouldNot()
            .HaveDependencyOn("Microsoft.AspNetCore.Authentication.Cookies")
            .GetResult();

        Assert.True(apiCheck.IsSuccessful, "API không được đăng ký CookieAuthentication cho access authentication.");

        var cookieConstants = typeof(SecurityCookieConstants)
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .Select(f => (f.Name, Value: f.GetValue(null)?.ToString() ?? string.Empty))
            .ToArray();

        Assert.DoesNotContain(cookieConstants, c =>
            string.Equals(c.Name, "AuthCookieName", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(c.Value, "__Host-SmartInvite.Auth", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Program_ShouldNotContainBusinessMethods()
    {
        var declaredMethods = typeof(Program)
            .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName && m.Name != "<Main>$")
            .ToArray();

        Assert.Empty(declaredMethods);
    }
}
