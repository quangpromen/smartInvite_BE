namespace SmartInvite.Domain.Common;

public sealed record Error(string Code, string Message, IReadOnlyDictionary<string, string[]>? Fields = null)
{
    public static readonly Error None = new(string.Empty, string.Empty);
    public static readonly Error NullValue = new(ErrorCodes.NullValue, "Giá trị cung cấp không được rỗng.");

    public static Error Internal(string message = "Đã xảy ra lỗi không mong muốn.") =>
        new(ErrorCodes.InternalError, message);

    public static Error Validation(string message, IReadOnlyDictionary<string, string[]>? fields = null) =>
        new(ErrorCodes.ValidationError, message, fields);

    public static Error Unauthorized(string code, string message) =>
        new(code, message);

    public static Error Forbidden(string message = "Bạn không có quyền thực hiện thao tác này.") =>
        new(ErrorCodes.Forbidden, message);

    public static Error NotFound(string code, string message) =>
        new(code, message);

    public static Error Conflict(string code, string message) =>
        new(code, message);

    public static Error Failure(string code, string message, IReadOnlyDictionary<string, string[]>? fields = null) =>
        new(code, message, fields);
}
