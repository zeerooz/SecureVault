using System.Net;
using System.Net.Http.Json;
using OtpNet;
using SecureVault.Api.Dtos;

namespace SecureVault.Tests.Integration;

public class TwoFactorTests(SecureVaultFactory factory) : IClassFixture<SecureVaultFactory>
{
    [Fact]
    public async Task Two_factor_can_be_set_up_enabled_and_then_used_to_log_in()
    {
        var client = factory.CreateClient();
        var (session, credentials) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);

        var setup = await client.PostAsync("/api/account/2fa/setup", null);
        setup.EnsureSuccessStatusCode();
        var secret = (await setup.Content.ReadFromJsonAsync<TwoFactorSetupResponse>())!.Secret;

        var enable = await client.PostAsJsonAsync("/api/account/2fa/enable",
            new EnableTwoFactorRequest(CodeFor(secret)));
        enable.EnsureSuccessStatusCode();

        var recoveryCodes = (await enable.Content.ReadFromJsonAsync<EnableTwoFactorResponse>())!.RecoveryCodes;
        Assert.Equal(8, recoveryCodes.Count);
        Assert.All(recoveryCodes, code => Assert.Matches("^[A-Z2-9]{5}-[A-Z2-9]{5}$", code));

        // A password-only login must now stop short of issuing tokens.
        var fresh = factory.CreateClient();
        var challenge = await fresh.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash
        });

        challenge.EnsureSuccessStatusCode();
        var body = await challenge.Content.ReadFromJsonAsync<TwoFactorRequiredResponse>();
        Assert.True(body!.RequiresTwoFactor);

        var completed = await fresh.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash,
            TwoFactorCode = CodeFor(secret)
        });

        completed.EnsureSuccessStatusCode();
        var loggedIn = await completed.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.True(loggedIn!.User.TwoFactorEnabled);
    }

    [Fact]
    public async Task Enabling_requires_a_code_that_actually_matches_the_secret()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);

        await client.PostAsync("/api/account/2fa/setup", null);

        var enable = await client.PostAsJsonAsync("/api/account/2fa/enable",
            new EnableTwoFactorRequest("000000"));

        Assert.Equal(HttpStatusCode.BadRequest, enable.StatusCode);

        // The account must not have been switched to two-factor on a failed proof.
        var me = await client.GetFromJsonAsync<UserSummary>("/api/auth/me");
        Assert.False(me!.TwoFactorEnabled);
    }

    [Fact]
    public async Task A_wrong_second_factor_fails_the_login()
    {
        var (credentials, _) = await EnrolledAccountAsync();
        var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash,
            TwoFactorCode = "123456"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_recovery_code_works_once_and_then_never_again()
    {
        var (credentials, recoveryCodes) = await EnrolledAccountAsync();
        var code = recoveryCodes[0];

        var client = factory.CreateClient();

        var first = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash,
            TwoFactorCode = code
        });
        first.EnsureSuccessStatusCode();

        var second = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = credentials.Email,
            AuthHash = credentials.AuthHash,
            TwoFactorCode = code
        });

        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
    }

    [Fact]
    public async Task Disabling_two_factor_requires_a_valid_code()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);

        var setup = await client.PostAsync("/api/account/2fa/setup", null);
        var secret = (await setup.Content.ReadFromJsonAsync<TwoFactorSetupResponse>())!.Secret;
        await client.PostAsJsonAsync("/api/account/2fa/enable", new EnableTwoFactorRequest(CodeFor(secret)));

        var refused = await client.PostAsJsonAsync("/api/account/2fa/disable",
            new DisableTwoFactorRequest("000000"));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        var accepted = await client.PostAsJsonAsync("/api/account/2fa/disable",
            new DisableTwoFactorRequest(CodeFor(secret)));
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);

        var me = await client.GetFromJsonAsync<UserSummary>("/api/auth/me");
        Assert.False(me!.TwoFactorEnabled);
    }

    private async Task<(RegisterRequest Credentials, IReadOnlyList<string> RecoveryCodes)> EnrolledAccountAsync()
    {
        var client = factory.CreateClient();
        var (session, credentials) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);

        var setup = await client.PostAsync("/api/account/2fa/setup", null);
        var secret = (await setup.Content.ReadFromJsonAsync<TwoFactorSetupResponse>())!.Secret;

        var enable = await client.PostAsJsonAsync("/api/account/2fa/enable",
            new EnableTwoFactorRequest(CodeFor(secret)));
        var codes = (await enable.Content.ReadFromJsonAsync<EnableTwoFactorResponse>())!.RecoveryCodes;

        return (credentials, codes);
    }

    private static string CodeFor(string secret) => new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp();
}
