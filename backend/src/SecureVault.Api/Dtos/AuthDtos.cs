using System.ComponentModel.DataAnnotations;
using SecureVault.Api.Domain;

namespace SecureVault.Api.Dtos;

/// <summary>
/// Step 1 of login. The client must know the account's KDF parameters before it
/// can derive a master key, so this endpoint is unauthenticated by necessity.
/// For unknown accounts it returns plausible deterministic parameters rather
/// than a 404, to avoid turning it into an account-enumeration oracle.
/// </summary>
public record PreloginRequest([Required, EmailAddress, MaxLength(256)] string Email);

public record PreloginResponse(KdfType KdfType, int KdfIterations, string KdfSalt);

public record RegisterRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public string Email { get; init; } = string.Empty;

    /// <summary>Base64 of PBKDF2(masterKey, masterPassword, 1 iteration). 32 bytes.</summary>
    [Required]
    public string AuthHash { get; init; } = string.Empty;

    /// <summary>Base64 of the 16-byte client-generated KDF salt.</summary>
    [Required]
    public string KdfSalt { get; init; } = string.Empty;

    [Range(100_000, 5_000_000)]
    public int KdfIterations { get; init; } = 600_000;

    /// <summary>Opaque AES-256-GCM blob holding the user's vault key.</summary>
    [Required, MaxLength(1024)]
    public string ProtectedVaultKey { get; init; } = string.Empty;
}

public record LoginRequest
{
    [Required, EmailAddress, MaxLength(256)]
    public string Email { get; init; } = string.Empty;

    [Required]
    public string AuthHash { get; init; } = string.Empty;

    /// <summary>6-digit TOTP code, or a recovery code, when 2FA is enabled.</summary>
    public string? TwoFactorCode { get; init; }
}

public record LoginResponse(
    string AccessToken,
    string RefreshToken,
    int ExpiresInSeconds,
    string ProtectedVaultKey,
    UserSummary User);

public record TwoFactorRequiredResponse(bool RequiresTwoFactor = true);

public record RefreshRequest([Required] string RefreshToken);

public record RefreshResponse(string AccessToken, string RefreshToken, int ExpiresInSeconds);

public record UserSummary(Guid Id, string Email, bool TwoFactorEnabled, DateTime CreatedAt);
