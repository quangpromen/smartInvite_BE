namespace SmartInvite.Infrastructure.Persistence;

public enum RefreshTokenState
{
    Active = 0,
    Rotated = 1,
    Revoked = 2,
    Expired = 3
}

public static class RefreshTokenRevokeReasons
{
    public const string Logout = "Logout";
    public const string LogoutAll = "LogoutAll";
    public const string ReuseDetected = "ReuseDetected";
    public const string AdminLocked = "AdminLocked";
    public const string AccountUnavailable = "AccountUnavailable";
}

public sealed class RefreshToken
{
    public const int TokenHashLength = 64;
    public const int MaxRevokedReasonLength = 64;

    private RefreshToken()
    {
    }

    public Guid Id { get; private set; }
    public Guid UserId { get; private set; }
    public string TokenHash { get; private set; } = string.Empty;
    public Guid FamilyId { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? RotatedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public Guid? ReplacedByTokenId { get; private set; }
    public string? RevokedReason { get; private set; }

    public bool IsRotated => RotatedAt.HasValue;
    public bool IsRevoked => RevokedAt.HasValue;

    public static RefreshToken Create(
        Guid userId,
        string tokenHash,
        Guid familyId,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        Guid? id = null)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("UserId không được rỗng.", nameof(userId));
        }

        if (familyId == Guid.Empty)
        {
            throw new ArgumentException("FamilyId không được rỗng.", nameof(familyId));
        }

        if (!IsValidSha256Hex(tokenHash))
        {
            throw new ArgumentException(
                "TokenHash bắt buộc phải là chuỗi băm SHA-256 hex 64 ký tự; không được truyền raw refresh token.",
                nameof(tokenHash));
        }

        if (expiresAt <= createdAt)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAt),
                "Thời điểm hết hạn refresh token phải lớn hơn thời điểm khởi tạo.");
        }

        var resolvedId = id is { } candidate && candidate != Guid.Empty
            ? candidate
            : Guid.NewGuid();

        return new RefreshToken
        {
            Id = resolvedId,
            UserId = userId,
            TokenHash = tokenHash.ToLowerInvariant(),
            FamilyId = familyId,
            CreatedAt = createdAt,
            ExpiresAt = expiresAt
        };
    }

    public bool IsExpired(DateTimeOffset utcNow) => ExpiresAt <= utcNow;

    public bool IsActive(DateTimeOffset utcNow) =>
        !IsRevoked && !IsRotated && !IsExpired(utcNow);

    public RefreshTokenState GetState(DateTimeOffset utcNow)
    {
        if (IsRevoked)
        {
            return RefreshTokenState.Revoked;
        }

        if (IsRotated)
        {
            return RefreshTokenState.Rotated;
        }

        if (IsExpired(utcNow))
        {
            return RefreshTokenState.Expired;
        }

        return RefreshTokenState.Active;
    }

    public void MarkRotated(DateTimeOffset rotatedAt, Guid replacedByTokenId)
    {
        if (replacedByTokenId == Guid.Empty)
        {
            throw new ArgumentException("ReplacedByTokenId không được rỗng.", nameof(replacedByTokenId));
        }

        if (IsRevoked || IsRotated)
        {
            throw new InvalidOperationException("Không thể xoay vòng refresh token đã bị thu hồi hoặc đã xoay vòng.");
        }

        RotatedAt = rotatedAt;
        ReplacedByTokenId = replacedByTokenId;
    }

    public void MarkRevoked(DateTimeOffset revokedAt, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        var trimmedReason = reason.Trim();
        if (trimmedReason.Length > MaxRevokedReasonLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(reason),
                $"Lý do thu hồi không được vượt quá {MaxRevokedReasonLength} ký tự.");
        }

        if (!RevokedAt.HasValue)
        {
            RevokedAt = revokedAt;
            RevokedReason = trimmedReason;
        }
    }

    public static bool IsValidSha256Hex(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length != TokenHashLength)
        {
            return false;
        }

        foreach (var ch in value)
        {
            var isHex = (ch is >= '0' and <= '9') ||
                        (ch is >= 'a' and <= 'f') ||
                        (ch is >= 'A' and <= 'F');
            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }
}

