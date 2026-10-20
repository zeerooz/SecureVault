using System.ComponentModel.DataAnnotations;
using SecureVault.Api.Domain;

namespace SecureVault.Api.Dtos;

public record VaultItemResponse(
    Guid Id,
    VaultItemType Type,
    string EncryptedData,
    int Revision,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public record CreateVaultItemRequest
{
    public VaultItemType Type { get; init; } = VaultItemType.Login;

    [Required, MaxLength(32768)]
    public string EncryptedData { get; init; } = string.Empty;
}

public record UpdateVaultItemRequest
{
    public VaultItemType Type { get; init; } = VaultItemType.Login;

    [Required, MaxLength(32768)]
    public string EncryptedData { get; init; } = string.Empty;

    /// <summary>Revision the client last read. Mismatch means someone else edited it first.</summary>
    [Range(1, int.MaxValue)]
    public int Revision { get; init; }
}
