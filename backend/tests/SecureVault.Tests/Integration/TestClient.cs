using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using SecureVault.Api.Dtos;

namespace SecureVault.Tests.Integration;

/// <summary>
/// Helpers that stand in for the browser crypto layer. The tests do not need
/// real PBKDF2 output — the server treats the auth hash as an opaque 32-byte
/// value — so random bytes of the right shape are enough.
/// </summary>
public static class TestClient
{
    public static string RandomAuthHash() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public static string RandomKdfSalt() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

    /// <summary>Stands in for an AES-GCM blob: 12-byte IV, body, 16-byte tag.</summary>
    public static string FakeCiphertext(int bodyBytes = 64) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(12 + bodyBytes + 16));

    public static string UniqueEmail() => $"user-{Guid.NewGuid():N}@example.com";

    public static RegisterRequest NewRegistration(string? email = null) => new()
    {
        Email = email ?? UniqueEmail(),
        AuthHash = RandomAuthHash(),
        KdfSalt = RandomKdfSalt(),
        KdfIterations = 600_000,
        ProtectedVaultKey = FakeCiphertext(32)
    };

    public static async Task<(LoginResponse Session, RegisterRequest Credentials)> RegisterAsync(
        this HttpClient client, string? email = null)
    {
        var registration = NewRegistration(email);
        var response = await client.PostAsJsonAsync("/api/auth/register", registration);
        response.EnsureSuccessStatusCode();

        var session = await response.Content.ReadFromJsonAsync<LoginResponse>();
        return (session!, registration);
    }

    public static void Authenticate(this HttpClient client, string accessToken) =>
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
}
