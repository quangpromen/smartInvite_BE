using Microsoft.OpenApi;
using SmartInvite.Api.Extensions;
using SmartInvite.Application.Security;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SmartInvite.Api.OpenApi;

public sealed class CsrfHeaderOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(context);

        var metadata = context.ApiDescription.ActionDescriptor.EndpointMetadata;
        if (!RequiresCsrfHeader(metadata))
        {
            return;
        }

        operation.Parameters ??= [];

        var alreadyExists = operation.Parameters.Any(parameter =>
            parameter.In == ParameterLocation.Header &&
            string.Equals(parameter.Name, SecurityCookieConstants.CsrfHeaderName, StringComparison.OrdinalIgnoreCase));

        if (alreadyExists)
        {
            return;
        }

        var httpMethod = context.ApiDescription.HttpMethod?.ToUpperInvariant() ?? "POST";

        operation.Parameters.Add(new OpenApiParameter
        {
            Name = SecurityCookieConstants.CsrfHeaderName,
            In = ParameterLocation.Header,
            Required = true,
            Description =
                $"Antiforgery request token bắt buộc cho endpoint sử dụng refresh cookie ({httpMethod}). " +
                "Lấy giá trị data.requestToken từ GET /api/auth/csrf.",
            Schema = new OpenApiSchema
            {
                Type = JsonSchemaType.String
            }
        });
    }

    public static bool RequiresCsrfHeader(IEnumerable<object>? endpointMetadata) =>
        endpointMetadata is not null &&
        endpointMetadata.OfType<ISmartInviteCsrfMetadata>().Any();
}
