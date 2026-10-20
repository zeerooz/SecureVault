using System.Net;
using System.Net.Http.Json;
using SecureVault.Api.Dtos;

namespace SecureVault.Tests.Integration;

public class SessionLifecycleTests(SecureVaultFactory factory) : IClassFixture<SecureVaultFactory>
{
    [Fact]
    public async Task A_refresh_token_can_be_exchanged_for_a_new_pair()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();

        var response = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(session.RefreshToken));
        response.EnsureSuccessStatusCode();

        var refreshed = await response.Content.ReadFromJsonAsync<RefreshResponse>();

        Assert.NotEqual(session.RefreshToken, refreshed!.RefreshToken);
        Assert.False(string.IsNullOrWhiteSpace(refreshed.AccessToken));
    }

    [Fact]
    public async Task A_refresh_token_cannot_be_used_twice()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();

        var first = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(session.RefreshToken));
        first.EnsureSuccessStatusCode();

        var replay = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(session.RefreshToken));

        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Replaying_an_old_token_kills_the_whole_family()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();

        var rotated = await (await client.PostAsJsonAsync("/api/auth/refresh",
            new RefreshRequest(session.RefreshToken))).Content.ReadFromJsonAsync<RefreshResponse>();

        // The attacker replays the stolen original.
        var replay = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(session.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // The victim's current token is now dead too: we cannot tell which of
        // the two parties is the thief, so both are logged out.
        var victim = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(rotated!.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, victim.StatusCode);
    }

    [Fact]
    public async Task A_garbage_refresh_token_is_rejected()
    {
        var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest("not-a-real-token"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_logged_out_refresh_token_stops_working()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);

        var logout = await client.PostAsJsonAsync("/api/auth/logout", new RefreshRequest(session.RefreshToken));
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var refresh = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(session.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task The_session_list_marks_the_current_device()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);

        var sessions = await client.GetFromJsonAsync<List<SessionResponse>>("/api/sessions");

        Assert.Single(sessions!);
        Assert.True(sessions![0].IsCurrent);
    }

    [Fact]
    public async Task Revoking_other_sessions_leaves_the_current_one_alive()
    {
        var email = TestClient.UniqueEmail();

        var firstDevice = factory.CreateClient();
        var (first, credentials) = await firstDevice.RegisterAsync(email);

        // A second sign-in from "another device".
        var secondDevice = factory.CreateClient();
        var loginResponse = await secondDevice.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash
        });
        var second = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        secondDevice.Authenticate(second!.AccessToken);

        var before = await secondDevice.GetFromJsonAsync<List<SessionResponse>>("/api/sessions");
        Assert.Equal(2, before!.Count);

        var revoke = await secondDevice.DeleteAsync("/api/sessions/others");
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        var after = await secondDevice.GetFromJsonAsync<List<SessionResponse>>("/api/sessions");
        Assert.Single(after!);
        Assert.True(after![0].IsCurrent);

        // The first device can no longer refresh.
        var orphaned = await firstDevice.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(first.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, orphaned.StatusCode);
    }
}
