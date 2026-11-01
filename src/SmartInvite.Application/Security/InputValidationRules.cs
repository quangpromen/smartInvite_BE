using System.Net.Mail;

namespace SmartInvite.Application.Security;

public static class IdentityFieldConstraints
{
    public const int MaxEmailLength = 256;
    public const int MaxDisplayNameLength = 150;
    public const int MinPasswordLength = 12;
    public const int MaxPasswordInputLength = 256;
    public const int RequiredUniquePasswordChars = 4;
    public const string AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
}

public static class InputValidationRules
{
    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || email.Length > IdentityFieldConstraints.MaxEmailLength)
        {
            return false;
        }

        foreach (var ch in email)
        {
            if (char.IsWhiteSpace(ch) || char.IsControl(ch))
            {
                return false;
            }
        }

        var atIndex = email.IndexOf('@');
        if (atIndex <= 0 || atIndex != email.LastIndexOf('@') || atIndex > 64 || atIndex >= email.Length - 3)
        {
            return false;
        }

        var localPart = email.AsSpan(0, atIndex);
        var domainPart = email.AsSpan(atIndex + 1);

        if (localPart[0] == '.' || localPart[^1] == '.' || localPart.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        if (!domainPart.Contains('.') || domainPart[0] == '.' || domainPart[^1] == '.' || domainPart.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        return MailAddress.TryCreate(email, out var parsed) &&
               string.Equals(parsed.Address, email, StringComparison.OrdinalIgnoreCase);
    }

    public static bool MeetsPasswordPolicy(string? password)
    {
        if (string.IsNullOrEmpty(password) ||
            password.Length < IdentityFieldConstraints.MinPasswordLength ||
            password.Length > IdentityFieldConstraints.MaxPasswordInputLength)
        {
            return false;
        }

        var hasUpper = false;
        var hasLower = false;
        var hasDigit = false;
        var hasNonAlphanumeric = false;
        var uniqueChars = new HashSet<char>();

        foreach (var ch in password)
        {
            uniqueChars.Add(ch);

            if (ch is >= 'A' and <= 'Z')
            {
                hasUpper = true;
            }
            else if (ch is >= 'a' and <= 'z')
            {
                hasLower = true;
            }
            else if (ch is >= '0' and <= '9')
            {
                hasDigit = true;
            }
            else
            {
                hasNonAlphanumeric = true;
            }
        }

        return hasUpper &&
               hasLower &&
               hasDigit &&
               hasNonAlphanumeric &&
               uniqueChars.Count >= IdentityFieldConstraints.RequiredUniquePasswordChars;
    }
}
