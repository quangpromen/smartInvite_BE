using System.Text;
using SmartInvite.Domain.Common;

namespace SmartInvite.Application.Auth;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";
    public const int MinimumSigningKeyBytes = 32;
    public const int MinimumDistinctSigningKeyBytes = 8;
    public const int MinAccessTokenMinutes = 1;
    public const int MaxAccessTokenMinutes = 60;
    public const int MinRefreshTokenDays = 1;
    public const int MaxRefreshTokenDays = 90;
    public const int MaxClockSkewSeconds = 60;
    public const int MaxIssuerOrAudienceLength = 256;

    public string Issuer { get; init; } = string.Empty;
    public string Audience { get; init; } = string.Empty;
    public string SigningKey { get; init; } = string.Empty;
    public int AccessTokenMinutes { get; init; } = 15;
    public int RefreshTokenDays { get; init; } = 7;
    public int ClockSkewSeconds { get; init; } = 30;
}

public static class JwtOptionsValidator
{
    public static Result Validate(JwtOptions? options)
    {
        var keyResult = ValidateAndResolveSigningKey(options);
        return keyResult.IsFailure
            ? Result.Failure(keyResult.Error)
            : Result.Success();
    }

    public static Result<byte[]> ValidateAndResolveSigningKey(JwtOptions? options)
    {
        if (options is null)
        {
            return Result.Failure<byte[]>(Error.Failure(
                ErrorCodes.TokenConfigurationInvalid,
                "Cấu hình Jwt bị thiếu."));
        }

        var problems = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            problems.Add("Jwt:Issuer bị thiếu");
        }
        else if (options.Issuer.Trim().Length > JwtOptions.MaxIssuerOrAudienceLength)
        {
            problems.Add($"Jwt:Issuer vượt quá {JwtOptions.MaxIssuerOrAudienceLength} ký tự");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            problems.Add("Jwt:Audience bị thiếu");
        }
        else if (options.Audience.Trim().Length > JwtOptions.MaxIssuerOrAudienceLength)
        {
            problems.Add($"Jwt:Audience vượt quá {JwtOptions.MaxIssuerOrAudienceLength} ký tự");
        }

        if (options.AccessTokenMinutes is < JwtOptions.MinAccessTokenMinutes or > JwtOptions.MaxAccessTokenMinutes)
        {
            problems.Add($"Jwt:AccessTokenMinutes phải nằm trong khoảng [{JwtOptions.MinAccessTokenMinutes}, {JwtOptions.MaxAccessTokenMinutes}]");
        }

        if (options.RefreshTokenDays is < JwtOptions.MinRefreshTokenDays or > JwtOptions.MaxRefreshTokenDays)
        {
            problems.Add($"Jwt:RefreshTokenDays phải nằm trong khoảng [{JwtOptions.MinRefreshTokenDays}, {JwtOptions.MaxRefreshTokenDays}]");
        }

        if (options.ClockSkewSeconds is < 0 or > JwtOptions.MaxClockSkewSeconds)
        {
            problems.Add($"Jwt:ClockSkewSeconds phải nằm trong khoảng [0, {JwtOptions.MaxClockSkewSeconds}]");
        }

        byte[]? signingKeyBytes = null;

        if (string.IsNullOrWhiteSpace(options.SigningKey))
        {
            problems.Add("Jwt:SigningKey (biến môi trường Jwt__SigningKey) bị thiếu");
        }
        else
        {
            var rawKey = options.SigningKey;

            if (rawKey.EndsWith('=') && TryDecodeBase64(rawKey, out var decodedBytes))
            {
                if (decodedBytes.Length < JwtOptions.MinimumSigningKeyBytes)
                {
                    problems.Add($"Jwt:SigningKey giải mã Base64 phải có tối thiểu {JwtOptions.MinimumSigningKeyBytes} bytes cho HMAC-SHA256");
                }
                else if (CountDistinctBytes(decodedBytes) < JwtOptions.MinimumDistinctSigningKeyBytes)
                {
                    problems.Add("Jwt:SigningKey không đủ độ ngẫu nhiên (entropy) tối thiểu cho HMAC-SHA256");
                }
            }

            var utf8Bytes = Encoding.UTF8.GetBytes(rawKey);
            if (utf8Bytes.Length < JwtOptions.MinimumSigningKeyBytes)
            {
                problems.Add($"Jwt:SigningKey phải có tối thiểu {JwtOptions.MinimumSigningKeyBytes} bytes cho HMAC-SHA256");
            }
            else if (CountDistinctBytes(utf8Bytes) < JwtOptions.MinimumDistinctSigningKeyBytes)
            {
                problems.Add("Jwt:SigningKey không đủ độ ngẫu nhiên (entropy) tối thiểu cho HMAC-SHA256");
            }
            else
            {
                signingKeyBytes = utf8Bytes;
            }
        }

        if (problems.Count > 0 || signingKeyBytes is null)
        {
            return Result.Failure<byte[]>(Error.Failure(
                ErrorCodes.TokenConfigurationInvalid,
                $"Cấu hình JWT không hợp lệ: {string.Join("; ", problems.Distinct(StringComparer.Ordinal))}."));
        }

        return Result.Success(signingKeyBytes);
    }

    private static bool TryDecodeBase64(string value, out byte[] decoded)
    {
        var buffer = new byte[(value.Length * 3) / 4 + 4];
        if (Convert.TryFromBase64String(value, buffer, out var bytesWritten))
        {
            decoded = buffer.AsSpan(0, bytesWritten).ToArray();
            return true;
        }

        decoded = [];
        return false;
    }

    private static int CountDistinctBytes(ReadOnlySpan<byte> bytes)
    {
        Span<bool> seen = stackalloc bool[256];
        var distinct = 0;

        foreach (var b in bytes)
        {
            if (!seen[b])
            {
                seen[b] = true;
                distinct++;
            }
        }

        return distinct;
    }
}

