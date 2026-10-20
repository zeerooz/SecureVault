namespace SecureVault.Api.Domain;

/// <summary>
/// A refresh-token family member. The raw refresh token is returned to the
/// client once and never stored; we keep only its SHA-256 hash, so a database
/// leak does not yield usable session tokens.
/// </summary>
public class Session
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    public byte[] RefreshTokenHash { get; set; } = [];

    /// <summary>Groups rotated tokens so reuse of an old one can revoke the whole chain.</summary>
    public Guid FamilyId { get; set; } = Guid.NewGuid();

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }

    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    public bool IsActive => RevokedAt is null && ExpiresAt > DateTimeOffset.UtcNow;
}
