namespace SecureVault.Api.Domain;

/// <summary>
/// A single-use 2FA bypass code. Stored as a SHA-256 hash; shown to the user
/// exactly once at the moment two-factor authentication is enabled.
/// </summary>
public class RecoveryCode
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    public byte[] CodeHash { get; set; } = [];

    public DateTimeOffset? UsedAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
