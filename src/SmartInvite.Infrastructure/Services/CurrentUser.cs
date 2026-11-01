using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using SmartInvite.Application.Abstractions;
using SmartInvite.Infrastructure.Identity;

namespace SmartInvite.Infrastructure.Services;

public class CurrentUser : ICurrentUser
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CurrentUser(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Guid? UserId
    {
        get
        {
            var user = _httpContextAccessor.HttpContext?.User;
            if (user is null)
            {
                return null;
            }

            var subValue = user.FindFirst(JwtClaimNames.Sub)?.Value;
            var nameIdValue = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!string.IsNullOrEmpty(subValue) &&
                !string.IsNullOrEmpty(nameIdValue) &&
                !string.Equals(subValue, nameIdValue, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var rawId = subValue ?? nameIdValue;
            return Guid.TryParse(rawId, out var parsed) && parsed != Guid.Empty
                ? parsed
                : null;
        }
    }

    public bool IsAuthenticated =>
        _httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated ?? false;

    public bool IsInRole(string role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            return false;
        }

        var user = _httpContextAccessor.HttpContext?.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        return user.IsInRole(role) ||
               user.Claims.Any(c =>
                   (string.Equals(c.Type, JwtClaimNames.Role, StringComparison.Ordinal) ||
                    string.Equals(c.Type, ClaimTypes.Role, StringComparison.Ordinal)) &&
                   string.Equals(c.Value, role, StringComparison.Ordinal));
    }
}
