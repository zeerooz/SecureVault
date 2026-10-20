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

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime LastSeenAt { get; set; } = DateTime.UtcNow;
    public DateTime? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }

    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    public bool IsActive => RevokedAt is null && ExpiresAt > DateTime.UtcNow;
}
