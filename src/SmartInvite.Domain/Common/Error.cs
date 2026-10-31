namespace SmartInvite.Domain.Common;

public sealed record Error(string Code, string Message, IReadOnlyDictionary<string, string[]>? Fields = null)
{
    public static readonly Error None = new(string.Empty, string.Empty);
    public static readonly Error NullValue = new("ERROR_NULL_VALUE", "Giá trị cung cấp không được rỗng.");

    public static Error Internal(string message = "Đã xảy ra lỗi không mong muốn.") =>
        new("INTERNAL_ERROR", message);

    public static Error Validation(string message, IReadOnlyDictionary<string, string[]>? fields = null) =>
        new("VALIDATION_ERROR", message, fields);

    public static Error NotFound(string code, string message) =>
        new(code, message);

    public static Error Conflict(string code, string message) =>
        new(code, message);
}

