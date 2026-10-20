namespace SecureVault.Api.Services;

/// <summary>
/// Protects the few secrets the server genuinely must be able to read back —
/// today that is only the TOTP shared secret. This is server-side encryption at
/// rest, NOT zero-knowledge: an attacker holding both the database and the
/// data-protection key can recover these values. Vault contents never pass
/// through here.
/// </summary>
public interface ISecretProtector
{
    string Protect(string plaintext);
    bool TryUnprotect(string? protectedValue, out string plaintext);
}
