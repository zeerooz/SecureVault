namespace SecureVault.Api.Domain;

/// <summary>
/// An account holder. The server stores only values it can safely see:
/// the KDF parameters the client needs to re-derive its master key, a hash of
/// the client-supplied authentication hash, and an opaque encrypted vault key.
/// The master password and the vault key itself never reach this table.
/// </summary>
public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Normalised (trimmed, lower-cased) email. Unique.</summary>
    public string Email { get; set; } = string.Empty;

    // --- Client-side KDF parameters -------------------------------------
    // Public by design: an attacker needs them to attempt an offline guess,
    // but so does the legitimate client before it can log in.

    public KdfType KdfType { get; set; } = KdfType.Pbkdf2Sha256;
    public int KdfIterations { get; set; }
    public byte[] KdfSalt { get; set; } = [];

    // --- Server-side verifier -------------------------------------------
    // The client sends authHash = PBKDF2(masterKey, masterPassword, 1).
    // We never store that value directly; we store Argon2id(authHash) so a
    // database leak does not hand the attacker a login credential.

    public byte[] AuthHashVerifier { get; set; } = [];
    public byte[] AuthHashSalt { get; set; } = [];

    // --- Opaque ciphertext ------------------------------------------------

    /// <summary>
    /// The user's 256-bit vault key, encrypted client-side under a key derived
    /// from the master password. Opaque to the server. Storing it this way lets
    /// the user change their master password without re-encrypting every item.
    /// </summary>
    public string ProtectedVaultKey { get; set; } = string.Empty;

    // --- Two-factor authentication ---------------------------------------
    // Honest caveat: the TOTP shared secret must be verifiable server-side, so
    // it is NOT zero-knowledge. It is encrypted at rest with a server-held key.
    // See docs/THREAT-MODEL.md, "What 2FA does and does not protect".

    public bool TwoFactorEnabled { get; set; }
    public string? TotpSecretProtected { get; set; }
    public List<RecoveryCode> RecoveryCodes { get; set; } = [];

    // --- Lockout ----------------------------------------------------------

    public int FailedLoginCount { get; set; }
    public DateTime? LockoutEndsAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public List<VaultItem> VaultItems { get; set; } = [];
    public List<Session> Sessions { get; set; } = [];

    public bool IsLockedOut => LockoutEndsAt is not null && LockoutEndsAt > DateTime.UtcNow;
}

public enum KdfType
{
    Pbkdf2Sha256 = 0
}
