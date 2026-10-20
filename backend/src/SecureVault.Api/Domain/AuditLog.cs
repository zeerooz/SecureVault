namespace SecureVault.Api.Domain;

/// <summary>
/// Append-only record of security-relevant events. Never contains plaintext
/// secrets, vault contents, or item names.
/// </summary>
public class AuditLog
{
    public long Id { get; set; }

    public Guid? UserId { get; set; }

    public AuditEvent Event { get; set; }

    /// <summary>Short, non-sensitive context, e.g. "item deleted" or "totp".</summary>
    public string? Detail { get; set; }

    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public enum AuditEvent
{
    RegisterSucceeded = 0,
    LoginSucceeded = 1,
    LoginFailed = 2,
    LoginLockedOut = 3,
    TwoFactorChallenged = 4,
    TwoFactorFailed = 5,
    TwoFactorEnabled = 6,
    TwoFactorDisabled = 7,
    TokenRefreshed = 8,
    TokenReuseDetected = 9,
    LoggedOut = 10,
    SessionRevoked = 11,
    MasterPasswordChanged = 12,
    VaultItemCreated = 13,
    VaultItemUpdated = 14,
    VaultItemDeleted = 15,
    RecoveryCodeUsed = 16
}
