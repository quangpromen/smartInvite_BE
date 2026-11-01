using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using SmartInvite.Application.Abstractions;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Identity;
using SmartInvite.Infrastructure.Services;
using Xunit;

namespace SmartInvite.UnitTests.Identity;

public class CurrentUserAndOwnershipTests
{
    [Fact]
    public void CurrentUser_ValidNameIdentifierGuid_ReturnsParsedGuidAndRoles()
    {
        var expectedId = Guid.NewGuid();
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, expectedId.ToString()),
            new Claim(ClaimTypes.Role, RoleNames.Host)
        };

        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "TestCookie"))
        };

        var currentUser = new CurrentUser(new HttpContextAccessor { HttpContext = httpContext });

        Assert.True(currentUser.IsAuthenticated);
        Assert.Equal(expectedId, currentUser.UserId);
        Assert.True(currentUser.IsInRole(RoleNames.Host));
        Assert.False(currentUser.IsInRole(RoleNames.Admin));
    }

    [Fact]
    public void CurrentUser_UnmappedJwtSubAndRoleClaims_ReturnsParsedGuidAndRoles_AndRejectsConflictingSubjectClaims()
    {
        var expectedId = Guid.NewGuid();
        var jwtClaims = new[]
        {
            new Claim("sub", expectedId.ToString()),
            new Claim("role", RoleNames.Admin)
        };

        var jwtContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(jwtClaims, authenticationType: "Bearer", nameType: "name", roleType: "role"))
        };

        var jwtCurrentUser = new CurrentUser(new HttpContextAccessor { HttpContext = jwtContext });
        Assert.True(jwtCurrentUser.IsAuthenticated);
        Assert.Equal(expectedId, jwtCurrentUser.UserId);
        Assert.True(jwtCurrentUser.IsInRole(RoleNames.Admin));
        Assert.False(jwtCurrentUser.IsInRole(RoleNames.Host));

        var conflictingClaims = new[]
        {
            new Claim("sub", expectedId.ToString()),
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
        };

        var conflictingContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(conflictingClaims, authenticationType: "Bearer"))
        };

        var conflictingUser = new CurrentUser(new HttpContextAccessor { HttpContext = conflictingContext });
        Assert.Null(conflictingUser.UserId);
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void CurrentUser_InvalidOrEmptyNameIdentifier_ReturnsNullWithoutThrowing(string invalidId)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, invalidId)
        };

        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "TestCookie"))
        };

        var currentUser = new CurrentUser(new HttpContextAccessor { HttpContext = httpContext });

        var exception = Record.Exception(() => _ = currentUser.UserId);

        Assert.Null(exception);
        Assert.Null(currentUser.UserId);
    }

    [Fact]
    public void CurrentUser_NullHttpContext_ReturnsUnauthenticatedDefaults()
    {
        var currentUser = new CurrentUser(new HttpContextAccessor { HttpContext = null });

        Assert.False(currentUser.IsAuthenticated);
        Assert.Null(currentUser.UserId);
        Assert.False(currentUser.IsInRole(RoleNames.Admin));
    }

    [Fact]
    public void ResourceOwnershipGuard_EnforcesExactHostOwnerMatch()
    {
        var ownerId = Guid.NewGuid();
        var otherHostId = Guid.NewGuid();

        var ownerGuard = new ResourceOwnershipGuard(new StubCurrentUser(ownerId, true, RoleNames.Host));
        var otherHostGuard = new ResourceOwnershipGuard(new StubCurrentUser(otherHostId, true, RoleNames.Host));
        var adminGuard = new ResourceOwnershipGuard(new StubCurrentUser(ownerId, true, RoleNames.Admin));
        var anonGuard = new ResourceOwnershipGuard(new StubCurrentUser(null, false, null));

        var resource = new SampleOwnedResource(ownerId);

        Assert.True(ownerGuard.IsOwner(resource));
        Assert.False(otherHostGuard.IsOwner(resource));
        Assert.False(adminGuard.IsOwner(resource));
        Assert.False(anonGuard.IsOwner(resource));
    }

    private sealed record SampleOwnedResource(Guid OwnerId) : IOwnedResource;

    private sealed class StubCurrentUser(Guid? userId, bool isAuthenticated, string? role) : ICurrentUser
    {
        public Guid? UserId => userId;
        public bool IsAuthenticated => isAuthenticated;
        public bool IsInRole(string candidateRole) =>
            isAuthenticated && string.Equals(role, candidateRole, StringComparison.Ordinal);
    }
}
