using SmartInvite.Application.Security;
using SmartInvite.Domain.Common;

namespace SmartInvite.Application.AdminHosts;

public sealed record ValidatedCreateHostInput(
    string Email,
    string DisplayName,
    string InitialPassword);

public static class AdminHostRequestValidator
{
    public static Result<ValidatedCreateHostInput> ValidateCreateHost(CreateHostRequest? request)
    {
        if (request is null)
        {
            return Result.Failure<ValidatedCreateHostInput>(Error.Validation(
                "Dữ liệu tạo Host không hợp lệ.",
                new Dictionary<string, string[]>
                {
                    ["request"] = ["Nội dung yêu cầu là bắt buộc."]
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

        var trimmedDisplayName = request.DisplayName?.Trim();
        if (string.IsNullOrWhiteSpace(trimmedDisplayName))
        {
            fields["displayName"] = ["Tên hiển thị là bắt buộc."];
        }
        else if (trimmedDisplayName.Length > IdentityFieldConstraints.MaxDisplayNameLength)
        {
            fields["displayName"] = [$"Tên hiển thị không được vượt quá {IdentityFieldConstraints.MaxDisplayNameLength} ký tự."];
        }

        // Tuyệt đối không trim hoặc biến đổi mật khẩu
        if (string.IsNullOrEmpty(request.InitialPassword))
        {
            fields["initialPassword"] = ["Mật khẩu khởi tạo là bắt buộc."];
        }
        else if (!InputValidationRules.MeetsPasswordPolicy(request.InitialPassword))
        {
            fields["initialPassword"] = ["Mật khẩu khởi tạo không đáp ứng chính sách bảo mật yêu cầu."];
        }

        if (fields.Count > 0)
        {
            return Result.Failure<ValidatedCreateHostInput>(Error.Validation("Dữ liệu tạo Host không hợp lệ.", fields));
        }

        return Result.Success(new ValidatedCreateHostInput(
            trimmedEmail!,
            trimmedDisplayName!,
            request.InitialPassword!));
    }

    public static Result ValidateHostId(Guid hostId)
    {
        if (hostId == Guid.Empty)
        {
            return Result.Failure(Error.Validation(
                "Mã định danh Host không hợp lệ.",
                new Dictionary<string, string[]>
                {
                    ["hostId"] = ["Mã định danh Host không được rỗng."]
                }));
        }

        return Result.Success();
    }

    public static Result ValidateLockUnlockTarget(
        Guid targetUserId,
        Guid actorUserId,
        bool isTargetHost,
        bool isTargetAdmin)
    {
        if (targetUserId == actorUserId)
        {
            return Result.Failure(Error.Failure(
                ErrorCodes.InvalidHostOperation,
                "Quản trị viên không thể khóa hoặc mở khóa tài khoản của chính mình."));
        }

        if (isTargetAdmin || !isTargetHost)
        {
            return Result.Failure(Error.Failure(
                ErrorCodes.InvalidHostOperation,
                "Chỉ được phép khóa hoặc mở khóa tài khoản có vai trò HOST."));
        }

        return Result.Success();
    }
}
