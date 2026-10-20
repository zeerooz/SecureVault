using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc;
using SecureVault.Api.Dtos;

namespace SecureVault.Tests.Integration;

public class AuthEndpointTests(SecureVaultFactory factory) : IClassFixture<SecureVaultFactory>
{
    [Fact]
    public async Task Register_returns_a_session_and_the_wrapped_vault_key()
    {
        var client = factory.CreateClient();
        var (session, credentials) = await client.RegisterAsync();

        Assert.False(string.IsNullOrWhiteSpace(session.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(session.RefreshToken));
        Assert.Equal(credentials.ProtectedVaultKey, session.ProtectedVaultKey);
        Assert.Equal(credentials.Email, session.User.Email);
        Assert.False(session.User.TwoFactorEnabled);
    }

    [Fact]
    public async Task Register_rejects_a_duplicate_email()
    {
        var client = factory.CreateClient();
        var email = TestClient.UniqueEmail();

        await client.RegisterAsync(email);
        var second = await client.PostAsJsonAsync("/api/auth/register", TestClient.NewRegistration(email));

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Register_rejects_an_auth_hash_that_is_not_32_bytes()
    {
        var client = factory.CreateClient();
        var registration = TestClient.NewRegistration() with { AuthHash = Convert.ToBase64String(new byte[8]) };

        var response = await client.PostAsJsonAsync("/api/auth/register", registration);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_succeeds_with_the_registered_auth_hash()
    {
        var client = factory.CreateClient();
        var (_, credentials) = await client.RegisterAsync();

        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash
        });

        response.EnsureSuccessStatusCode();
        var session = await response.Content.ReadFromJsonAsync<LoginResponse>();

        Assert.Equal(credentials.ProtectedVaultKey, session!.ProtectedVaultKey);
    }

    [Fact]
    public async Task Login_is_case_insensitive_about_the_email()
    {
        var client = factory.CreateClient();
        var (_, credentials) = await client.RegisterAsync();

        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email.ToUpperInvariant(),
            AuthHash = credentials.AuthHash
        });

        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Login_fails_with_the_wrong_auth_hash()
    {
        var client = factory.CreateClient();
        var (_, credentials) = await client.RegisterAsync();

        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = TestClient.RandomAuthHash()
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_unknown_account_and_a_wrong_password_are_indistinguishable()
    {
        var client = factory.CreateClient();
        var (_, credentials) = await client.RegisterAsync();

        var unknown = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = TestClient.UniqueEmail(),
            AuthHash = TestClient.RandomAuthHash()
        });

        var wrongPassword = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = TestClient.RandomAuthHash()
        });

        Assert.Equal(unknown.StatusCode, wrongPassword.StatusCode);

        // Compare the meaningful fields rather than the raw body: ProblemDetails
        // carries a per-request traceId, which differs by design and leaks nothing.
        var unknownBody = await unknown.Content.ReadFromJsonAsync<ProblemDetails>();
        var wrongPasswordBody = await wrongPassword.Content.ReadFromJsonAsync<ProblemDetails>();

        Assert.Equal(unknownBody!.Title, wrongPasswordBody!.Title);
        Assert.Equal(unknownBody.Detail, wrongPasswordBody.Detail);
        Assert.Equal(unknownBody.Status, wrongPasswordBody.Status);
    }

    [Fact]
    public async Task Prelogin_does_not_reveal_whether_an_account_exists()
    {
        var client = factory.CreateClient();
        var (_, credentials) = await client.RegisterAsync();

        var known = await client.PostAsJsonAsync("/api/auth/prelogin", new PreloginRequest(credentials.Email));
        var unknown = await client.PostAsJsonAsync("/api/auth/prelogin", new PreloginRequest(TestClient.UniqueEmail()));

        Assert.Equal(HttpStatusCode.OK, known.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unknown.StatusCode);

        var knownBody = await known.Content.ReadFromJsonAsync<PreloginResponse>();
        var unknownBody = await unknown.Content.ReadFromJsonAsync<PreloginResponse>();

        // Same shape, same iteration count, a salt of the same length.
        Assert.Equal(knownBody!.KdfIterations, unknownBody!.KdfIterations);
        Assert.Equal(
            Convert.FromBase64String(knownBody.KdfSalt).Length,
            Convert.FromBase64String(unknownBody.KdfSalt).Length);
    }

    [Fact]
    public async Task Prelogin_returns_a_stable_decoy_salt_for_the_same_unknown_email()
    {
        var client = factory.CreateClient();
        var email = TestClient.UniqueEmail();

        var first = await client.PostAsJsonAsync("/api/auth/prelogin", new PreloginRequest(email));
        var second = await client.PostAsJsonAsync("/api/auth/prelogin", new PreloginRequest(email));

        var firstBody = await first.Content.ReadFromJsonAsync<PreloginResponse>();
        var secondBody = await second.Content.ReadFromJsonAsync<PreloginResponse>();

        // A salt that changed per request would itself be the tell.
        Assert.Equal(firstBody!.KdfSalt, secondBody!.KdfSalt);
    }

    [Fact]
    public async Task Me_requires_authentication()
    {
        var client = factory.CreateClient();

        var response = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Me_returns_the_authenticated_account()
    {
        var client = factory.CreateClient();
        var (session, credentials) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);

        var summary = await client.GetFromJsonAsync<UserSummary>("/api/auth/me");

        Assert.Equal(credentials.Email, summary!.Email);
    }

    [Fact]
    public async Task A_tampered_access_token_is_rejected()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();

        // Flip the final character of the signature.
        var tampered = session.AccessToken[..^1] + (session.AccessToken[^1] == 'A' ? 'B' : 'A');
        client.Authenticate(tampered);

        var response = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
