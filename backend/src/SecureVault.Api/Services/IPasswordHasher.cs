namespace SecureVault.Api.Services;

public interface IPasswordHasher
{
    /// <summary>Hashes the client-supplied auth hash with a fresh random salt.</summary>
    (byte[] Hash, byte[] Salt) Hash(string base64AuthHash);

    /// <summary>Constant-time verification. Returns false for malformed input rather than throwing.</summary>
    bool Verify(string base64AuthHash, byte[] expectedHash, byte[] salt);
}
