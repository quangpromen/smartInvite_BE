using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;

namespace SmartInvite.Application.Auth;

public static class AuthRequestValidator
{
    public static Result<string> ValidateLogin(LoginRequest? request)
    {
        if (request is null)
        {
            return Result.Failure<string>(Error.Validation(
                "Dữ liệu đăng nhập không hợp lệ.",
                new Dictionary<string, string[]>
                {
                    ["request"] = ["Nội dung yêu cầu đăng nhập là bắt buộc."]
                }));
        }

        var fields = new Dictionary<string, string[]>();

        var trimmedEmail = request.Email?.Trim();
        if (string.IsNullOrWhiteSpace(trimmedEmail))
        {
            fields["email"] = ["Email là bắt buộc."];
        }
        else if (trimmedEmail.Length > IdentityFieldConstraints.MaxEmailLength)
        {
            fields["email"] = [$"Email không được vượt quá {IdentityFieldConstraints.MaxEmailLength} ký tự."];
        }
        else if (!InputValidationRules.IsValidEmail(trimmedEmail))
        {
            fields["email"] = ["Định dạng email không hợp lệ."];
        }

        // Tuyệt đối không trim hoặc biến đổi mật khẩu
        if (string.IsNullOrEmpty(request.Password))
        {
            fields["password"] = ["Mật khẩu là bắt buộc."];
        }
        else if (request.Password.Length > IdentityFieldConstraints.MaxPasswordInputLength)
        {
            fields["password"] = [$"Độ dài mật khẩu không được vượt quá {IdentityFieldConstraints.MaxPasswordInputLength} ký tự."];
        }

        if (fields.Count > 0)
        {
            return Result.Failure<string>(Error.Validation("Thông tin đăng nhập không hợp lệ.", fields));
        }

        return Result.Success(trimmedEmail!);
    }
}
