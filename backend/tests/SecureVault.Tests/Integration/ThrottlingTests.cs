using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using SecureVault.Api.Dtos;

namespace SecureVault.Tests.Integration;

/// <summary>A factory whose authentication rate limit is low enough to trip deliberately.</summary>
public class ThrottledFactory : SecureVaultFactory
{
    public const int AuthPermitPerMinute = 5;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("RateLimits:AuthPermitPerMinute", AuthPermitPerMinute.ToString());
    }
}

public class RateLimitTests(ThrottledFactory factory) : IClassFixture<ThrottledFactory>
{
    [Fact]
    public async Task The_authentication_routes_start_refusing_once_the_window_is_spent()
    {
        var client = factory.CreateClient();
        var statuses = new List<HttpStatusCode>();

        for (var i = 0; i < ThrottledFactory.AuthPermitPerMinute + 3; i++)
        {
            var response = await client.PostAsJsonAsync("/api/auth/prelogin",
                new PreloginRequest($"probe-{i}@example.com"));

            statuses.Add(response.StatusCode);
        }

        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);

        // The limit must bite only after the allowance, not before it.
        Assert.All(statuses.Take(ThrottledFactory.AuthPermitPerMinute),
            status => Assert.Equal(HttpStatusCode.OK, status));
    }
}

/// <summary>A factory that locks an account out after very few failures.</summary>
public class LockoutFactory : SecureVaultFactory
{
    public const int MaxFailedAttempts = 3;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Lockout:MaxFailedAttempts", MaxFailedAttempts.ToString());
        builder.UseSetting("Lockout:LockoutMinutes", "15");
    }
}

public class AccountLockoutTests(LockoutFactory factory) : IClassFixture<LockoutFactory>
{
    [Fact]
    public async Task Repeated_failures_lock_the_account_even_for_the_right_password()
    {
        var client = factory.CreateClient();
        var (_, credentials) = await client.RegisterAsync();

        for (var i = 0; i < LockoutFactory.MaxFailedAttempts; i++)
        {
            var attempt = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = credentials.Email,
                AuthHash = TestClient.RandomAuthHash()
            });

            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        // The genuine master password is now refused too. That is the point:
        // an online guessing attack is stopped without the attacker learning
        // whether any individual guess was close.
        var correct = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash
        });

        Assert.Equal(HttpStatusCode.Unauthorized, correct.StatusCode);
    }

    [Fact]
    public async Task A_failed_attempt_on_one_account_does_not_lock_another()
    {
        var client = factory.CreateClient();
        var (_, victim) = await client.RegisterAsync();
        var (_, bystander) = await client.RegisterAsync();

        for (var i = 0; i < LockoutFactory.MaxFailedAttempts; i++)
        {
            await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = victim.Email,
                AuthHash = TestClient.RandomAuthHash()
            });
        }

        var unaffected = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = bystander.Email,
            AuthHash = bystander.AuthHash
        });

        unaffected.EnsureSuccessStatusCode();
    }
}
