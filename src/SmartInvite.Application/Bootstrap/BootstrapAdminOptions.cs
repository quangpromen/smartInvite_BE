using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;

namespace SmartInvite.Application.Bootstrap;

public sealed class BootstrapAdminOptions
{
    public const string SectionName = "BootstrapAdmin";

    public bool Enabled { get; init; }
    public string Email { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
}

public static class BootstrapAdminValidator
{
    public static Result Validate(BootstrapAdminOptions? options)
    {
        if (options is null || !options.Enabled)
        {
            return Result.Success();
        }

        var missingOrInvalid = new List<string>();

        var trimmedEmail = options.Email?.Trim();
        if (string.IsNullOrWhiteSpace(trimmedEmail))
        {
            missingOrInvalid.Add("BootstrapAdmin:Email bị thiếu");
        }
        else if (!InputValidationRules.IsValidEmail(trimmedEmail))
        {
            missingOrInvalid.Add("BootstrapAdmin:Email không đúng định dạng hợp lệ");
        }

        if (string.IsNullOrEmpty(options.Password))
        {
            missingOrInvalid.Add("BootstrapAdmin:Password bị thiếu");
        }
        else if (!InputValidationRules.MeetsPasswordPolicy(options.Password))
        {
            missingOrInvalid.Add("BootstrapAdmin:Password không đáp ứng chính sách độ mạnh mật khẩu");
        }

        var trimmedDisplayName = options.DisplayName?.Trim();
        if (string.IsNullOrWhiteSpace(trimmedDisplayName))
        {
            missingOrInvalid.Add("BootstrapAdmin:DisplayName bị thiếu");
        }
        else if (trimmedDisplayName.Length > IdentityFieldConstraints.MaxDisplayNameLength)
        {
            missingOrInvalid.Add($"BootstrapAdmin:DisplayName vượt quá {IdentityFieldConstraints.MaxDisplayNameLength} ký tự");
        }

        if (missingOrInvalid.Count > 0)
        {
            return Result.Failure(Error.Validation(
                $"Cấu hình BootstrapAdmin không hợp lệ khi Enabled=true: {string.Join("; ", missingOrInvalid)}."));
        }

        return Result.Success();
    }
}
