using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace SmartInvite.Infrastructure.Identity;

public static class JwtClaimNames
{
    public const string Sub = "sub";
    public const string Email = "email";
    public const string Name = "name";
    public const string Role = "role";
    public const string Jti = "jti";
    public const string Iat = "iat";
    public const string Nbf = "nbf";
    public const string Exp = "exp";
    public const string Iss = "iss";
    public const string Aud = "aud";
    public const string SecurityStampHash = "sst";
}

internal static class TokenCryptoHelper
{
    public const int MinimumRefreshTokenEntropyBytes = 64;

    public static string GenerateSecureRefreshToken(int byteLength = MinimumRefreshTokenEntropyBytes)
    {
        if (byteLength < MinimumRefreshTokenEntropyBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(byteLength),
                $"Refresh token phải có tối thiểu {MinimumRefreshTokenEntropyBytes} random bytes.");
        }

        var randomBytes = RandomNumberGenerator.GetBytes(byteLength);
        return Base64Url.EncodeToString(randomBytes);
    }

    public static string ComputeSha256Hex(string rawValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawValue);

        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawValue));
        return Convert.ToHexStringLower(hashBytes);
    }

    public static bool FixedTimeEqualsSha256Hex(string? candidateHex, string currentRawValue)
    {
        if (string.IsNullOrWhiteSpace(currentRawValue) ||
            string.IsNullOrEmpty(candidateHex) ||
            candidateHex.Length != 64)
        {
            return false;
        }

        byte[] candidateBytes;
        try
        {
            candidateBytes = Convert.FromHexString(candidateHex);
        }
        catch (FormatException)
        {
            return false;
        }

        var expectedBytes = SHA256.HashData(Encoding.UTF8.GetBytes(currentRawValue));
        return CryptographicOperations.FixedTimeEquals(candidateBytes, expectedBytes);
    }
}

