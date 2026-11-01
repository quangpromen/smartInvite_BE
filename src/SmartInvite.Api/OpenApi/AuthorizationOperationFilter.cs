using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi;
using SmartInvite.Api.Extensions;
using SmartInvite.Application.Security;
using SmartInvite.Domain.Identity;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SmartInvite.Api.OpenApi;

public sealed class AuthorizationOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(context);

        var metadata = context.ApiDescription.ActionDescriptor.EndpointMetadata;
        var hasAllowAnonymous = metadata.OfType<IAllowAnonymous>().Any();
        var authorizeData = metadata.OfType<IAuthorizeData>().ToArray();

        if (hasAllowAnonymous || authorizeData.Length == 0)
        {
            operation.Security?.Clear();
            AppendAccessLevelNote(
                operation,
                "**Quyền truy cập:** `Anonymous` (Không yêu cầu header `Authorization: Bearer`).");
            return;
        }

        operation.Security ??= [];

        var hasBearerScheme = operation.Security.Any(requirement =>
            requirement.Keys.Any(scheme =>
                string.Equals(
                    scheme.Reference?.Id,
                    OpenApiExtensions.BearerSecuritySchemeName,
                    StringComparison.Ordinal)));

        if (!hasBearerScheme)
        {
            var schemeReference = new OpenApiSecuritySchemeReference(
                OpenApiExtensions.BearerSecuritySchemeName,
                context.Document);

            operation.Security.Add(new OpenApiSecurityRequirement
            {
                [schemeReference] = []
            });
        }

        if (IsAdminOnly(authorizeData))
        {
            AppendAccessLevelNote(
                operation,
                $"**Quyền truy cập:** `ADMIN only` (Yêu cầu JWT Bearer access token của tài khoản có vai trò `{RoleNames.Admin}`).");
            return;
        }

        if (IsHostOnly(authorizeData))
        {
            AppendAccessLevelNote(
                operation,
                $"**Quyền truy cập:** `HOST only` (Yêu cầu JWT Bearer access token của tài khoản có vai trò `{RoleNames.Host}`).");
            return;
        }

        AppendAccessLevelNote(
            operation,
            "**Quyền truy cập:** `Authenticated` (Yêu cầu JWT Bearer access token hợp lệ trong header `Authorization`).");
    }

    private static bool IsAdminOnly(IEnumerable<IAuthorizeData> authorizeData) =>
        authorizeData.Any(item =>
            string.Equals(item.Policy, AuthorizationPolicies.AdminOnly, StringComparison.Ordinal) ||
            ContainsRole(item.Roles, RoleNames.Admin));

    private static bool IsHostOnly(IEnumerable<IAuthorizeData> authorizeData) =>
        authorizeData.Any(item =>
            string.Equals(item.Policy, AuthorizationPolicies.HostOnly, StringComparison.Ordinal) ||
            ContainsRole(item.Roles, RoleNames.Host));

    private static bool ContainsRole(string? rolesCsv, string expectedRole) =>
        !string.IsNullOrWhiteSpace(rolesCsv) &&
        rolesCsv
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(expectedRole, StringComparer.OrdinalIgnoreCase);

    private static void AppendAccessLevelNote(OpenApiOperation operation, string accessNote)
    {
        if (string.IsNullOrWhiteSpace(operation.Description))
        {
            operation.Description = accessNote;
            return;
        }

        if (!operation.Description.Contains(accessNote, StringComparison.Ordinal))
        {
            operation.Description = $"{operation.Description}\n\n{accessNote}";
        }
    }
}
