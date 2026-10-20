using Microsoft.AspNetCore.DataProtection;

namespace SecureVault.Api.Services;

public class DataProtectionSecretProtector : ISecretProtector
{
    private readonly IDataProtector _protector;

    public DataProtectionSecretProtector(IDataProtectionProvider provider)
    {
        // The purpose string scopes the derived key: a ciphertext produced here
        // cannot be decrypted by a protector created for any other purpose.
        _protector = provider.CreateProtector("SecureVault.TotpSecret.v1");
    }

    public string Protect(string plaintext) => _protector.Protect(plaintext);

    public bool TryUnprotect(string? protectedValue, out string plaintext)
    {
        plaintext = string.Empty;

        if (string.IsNullOrWhiteSpace(protectedValue))
        {
            return false;
        }

        try
        {
            plaintext = _protector.Unprotect(protectedValue);
            return true;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Wrong key ring, tampered payload, or a rotated-away key.
            return false;
        }
    }
}
