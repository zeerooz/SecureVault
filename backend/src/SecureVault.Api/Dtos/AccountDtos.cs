using System.ComponentModel.DataAnnotations;

namespace SecureVault.Api.Dtos;

public record TwoFactorSetupResponse(string Secret, string OtpAuthUri);

public record EnableTwoFactorRequest([property: Required, MinLength(6), MaxLength(10)] string Code);

public record EnableTwoFactorResponse(IReadOnlyList<string> RecoveryCodes);

public record DisableTwoFactorRequest([property: Required, MinLength(6), MaxLength(16)] string Code);

/// <summary>
/// Changing the master password re-wraps the vault key; it does not re-encrypt
/// the items, because the vault key itself is unchanged.
/// </summary>
public record ChangeMasterPasswordRequest
{
    [Required] public string CurrentAuthHash { get; init; } = string.Empty;
    [Required] public string NewAuthHash { get; init; } = string.Empty;
    [Required] public string NewKdfSalt { get; init; } = string.Empty;
    [Range(100_000, 5_000_000)] public int NewKdfIterations { get; init; } = 600_000;
    [Required, MaxLength(1024)] public string NewProtectedVaultKey { get; init; } = string.Empty;
}

public record SessionResponse(
    Guid Id,
    string? IpAddress,
    string? UserAgent,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastSeenAt,
    DateTimeOffset ExpiresAt,
    bool IsCurrent);

public record AuditLogResponse(long Id, string Event, string? Detail, string? IpAddress, DateTimeOffset CreatedAt);
