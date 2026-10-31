using SmartInvite.Domain.Common;
using Xunit;

namespace SmartInvite.UnitTests.Common;

public class ResultTests
{
    [Fact]
    public void Success_ShouldCreateSuccessfulResult()
    {
        // Act
        var result = Result.Success();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.False(result.IsFailure);
        Assert.Equal(Error.None, result.Error);
    }

    [Fact]
    public void Failure_ShouldCreateFailedResultWithErrorDetails()
    {
        // Arrange
        var error = Error.Validation("Dữ liệu đầu vào không hợp lệ.");

        // Act
        var result = Result.Failure(error);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.True(result.IsFailure);
        Assert.Equal("VALIDATION_ERROR", result.Error.Code);
        Assert.Equal("Dữ liệu đầu vào không hợp lệ.", result.Error.Message);
    }

    [Fact]
    public void GenericSuccess_ShouldContainProvidedValue()
    {
        // Arrange
        const string expectedValue = "smart-invite-test";

        // Act
        var result = Result.Success(expectedValue);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(expectedValue, result.Value);
    }

    [Fact]
    public void GenericFailure_AccessingValue_ShouldThrowInvalidOperationException()
    {
        // Arrange
        var error = Error.NotFound("EVENT_NOT_FOUND", "Không tìm thấy sự kiện.");
        var result = Result.Failure<string>(error);

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => _ = result.Value);
        Assert.Contains("Không thể truy xuất giá trị từ một kết quả thất bại.", exception.Message);
    }
}

