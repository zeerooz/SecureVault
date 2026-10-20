using SecureVault.Api.Services;

namespace SecureVault.Tests.Unit;

public class Argon2PasswordHasherTests
{
    private readonly Argon2PasswordHasher _hasher = new();

    private const string AuthHash = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaQ==";

    [Fact]
    public void Verify_accepts_the_value_that_was_hashed()
    {
        var (hash, salt) = _hasher.Hash(AuthHash);

        Assert.True(_hasher.Verify(AuthHash, hash, salt));
    }

    [Fact]
    public void Verify_rejects_a_different_value()
    {
        var (hash, salt) = _hasher.Hash(AuthHash);

        Assert.False(_hasher.Verify("c29tZXRoaW5nLWVsc2UtZW50aXJlbHktZGlmZmVyZW50", hash, salt));
    }

    [Fact]
    public void Hashing_the_same_value_twice_produces_different_output()
    {
        var (first, firstSalt) = _hasher.Hash(AuthHash);
        var (second, secondSalt) = _hasher.Hash(AuthHash);

        // A fresh salt per hash is what stops an attacker from spotting that
        // two accounts share a master password.
        Assert.NotEqual(firstSalt, secondSalt);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Verify_returns_false_for_empty_stored_values_instead_of_throwing()
    {
        Assert.False(_hasher.Verify(AuthHash, [], []));
    }

    [Fact]
    public void A_hash_is_not_valid_against_a_foreign_salt()
    {
        var (hash, _) = _hasher.Hash(AuthHash);
        var (_, otherSalt) = _hasher.Hash(AuthHash);

        Assert.False(_hasher.Verify(AuthHash, hash, otherSalt));
    }
}
