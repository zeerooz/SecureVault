using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace SecureVault.Api.Services;

/// <summary>
/// Argon2id over the client-supplied auth hash.
///
/// Why a second hash at all? The client already ran 600k PBKDF2 iterations, but
/// what it sends us is, from the server's point of view, just a password-equivalent
/// bearer value. If we stored it verbatim, a database leak would hand the attacker
/// a working login for every account. Argon2id makes the stored verifier useless
/// on its own and expensive to brute-force.
///
/// Parameters follow the OWASP Password Storage Cheat Sheet baseline for Argon2id:
/// m = 19 MiB, t = 2, p = 1.
/// </summary>
public class Argon2PasswordHasher : IPasswordHasher
{
    private const int MemoryKiB = 19 * 1024;
    private const int Iterations = 2;
    private const int Parallelism = 1;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public (byte[] Hash, byte[] Salt) Hash(string base64AuthHash)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        return (Derive(base64AuthHash, salt), salt);
    }

    public bool Verify(string base64AuthHash, byte[] expectedHash, byte[] salt)
    {
        if (expectedHash.Length == 0 || salt.Length == 0)
        {
            return false;
        }

        var actual = Derive(base64AuthHash, salt);
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }

    private static byte[] Derive(string base64AuthHash, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(base64AuthHash))
        {
            Salt = salt,
            MemorySize = MemoryKiB,
            Iterations = Iterations,
            DegreeOfParallelism = Parallelism
        };

        return argon2.GetBytes(HashBytes);
    }
}
