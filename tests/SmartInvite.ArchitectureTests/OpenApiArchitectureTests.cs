using NetArchTest.Rules;
using Xunit;

namespace SmartInvite.ArchitectureTests;

public class OpenApiArchitectureTests
{
    private static readonly string[] OpenApiNamespaces =
    [
        "Swashbuckle",
        "Microsoft.OpenApi"
    ];

    [Fact]
    public void Domain_Application_And_Infrastructure_ShouldNotDependOn_SwaggerOrOpenApiPackages()
    {
        var nonApiAssemblies = new[]
        {
            ("Domain", Domain.AssemblyReference.Assembly),
            ("Application", Application.AssemblyReference.Assembly),
            ("Infrastructure", Infrastructure.AssemblyReference.Assembly)
        };

        foreach (var (layerName, assembly) in nonApiAssemblies)
        {
            var typeDependencyResult = Types.InAssembly(assembly)
                .ShouldNot()
                .HaveDependencyOnAny(OpenApiNamespaces)
                .GetResult();

            Assert.True(
                typeDependencyResult.IsSuccessful,
                $"{layerName} không được phép phụ thuộc vào Swashbuckle hoặc Microsoft.OpenApi.");

            var referencedAssemblies = assembly.GetReferencedAssemblies()
                .Select(a => a.Name ?? string.Empty)
                .ToArray();

            Assert.DoesNotContain(referencedAssemblies, name =>
                name.StartsWith("Swashbuckle", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Microsoft.OpenApi", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Microsoft.AspNetCore.OpenApi", StringComparison.OrdinalIgnoreCase));
        }
    }
}

