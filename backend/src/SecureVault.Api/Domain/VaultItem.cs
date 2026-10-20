namespace SecureVault.Api.Domain;

/// <summary>
/// One vault entry. Everything the user typed lives inside <see cref="EncryptedData"/>,
/// an AES-256-GCM blob the server cannot read. The columns outside it are the
/// deliberate metadata leak documented in the threat model: we know how many
/// items you have and when you touched them, not what they are.
/// </summary>
public class VaultItem
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    /// <summary>
    /// Kept in plaintext so the client can render the right icon without
    /// decrypting every item first. Reveals a category, never a value.
    /// </summary>
    public VaultItemType Type { get; set; } = VaultItemType.Login;

    /// <summary>Base64 of: 12-byte IV || ciphertext || 16-byte GCM tag.</summary>
    public string EncryptedData { get; set; } = string.Empty;

    /// <summary>Optimistic-concurrency guard so two tabs cannot silently clobber each other.</summary>
    public int Revision { get; set; } = 1;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public enum VaultItemType
{
    Login = 0,
    SecureNote = 1,
    Card = 2
}
