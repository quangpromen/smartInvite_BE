using NetArchTest.Rules;
using Xunit;

namespace SmartInvite.ArchitectureTests;

public class ArchitectureTests
{
    private const string DomainNamespace = "SmartInvite.Domain";
    private const string ApplicationNamespace = "SmartInvite.Application";
    private const string InfrastructureNamespace = "SmartInvite.Infrastructure";
    private const string ApiNamespace = "SmartInvite.Api";

    [Fact]
    public void Domain_ShouldNotHaveDependencyOnApplication_Infrastructure_OrApi()
    {
        var result = Types.InAssembly(Domain.AssemblyReference.Assembly)
            .ShouldNot()
            .HaveDependencyOnAny(ApplicationNamespace, InfrastructureNamespace, ApiNamespace)
            .GetResult();

        Assert.True(result.IsSuccessful, "Domain không được phụ thuộc vào Application, Infrastructure hoặc Api.");
    }

    [Fact]
    public void Application_ShouldNotHaveDependencyOnInfrastructure_OrApi()
    {
        var result = Types.InAssembly(Application.AssemblyReference.Assembly)
            .ShouldNot()
            .HaveDependencyOnAny(InfrastructureNamespace, ApiNamespace)
            .GetResult();

        Assert.True(result.IsSuccessful, "Application không được phụ thuộc vào Infrastructure hoặc Api.");
    }

    [Fact]
    public void Infrastructure_ShouldNotHaveDependencyOnApi()
    {
        var result = Types.InAssembly(Infrastructure.AssemblyReference.Assembly)
            .ShouldNot()
            .HaveDependencyOn(ApiNamespace)
            .GetResult();

        Assert.True(result.IsSuccessful, "Infrastructure không được phụ thuộc vào Api.");
    }
}

