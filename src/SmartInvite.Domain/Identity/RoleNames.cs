namespace SmartInvite.Domain.Identity;

public static class RoleNames
{
    public const string Admin = "ADMIN";
    public const string Host = "HOST";

    public static readonly IReadOnlyList<string> All = [Admin, Host];

    public static bool IsKnownRole(string? role) =>
        string.Equals(role, Admin, StringComparison.Ordinal) ||
        string.Equals(role, Host, StringComparison.Ordinal);
}
