using OtpNet;
using SecureVault.Api.Services;

namespace SecureVault.Tests.Unit;

public class TotpServiceTests
{
    private readonly TotpService _totp = new();

    [Fact]
    public void A_freshly_generated_secret_validates_a_current_code()
    {
        var secret = _totp.GenerateSecret();
        var code = new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp();

        Assert.True(_totp.VerifyCode(secret, code));
    }

    [Fact]
    public void A_code_from_a_different_secret_is_rejected()
    {
        var secret = _totp.GenerateSecret();
        var otherSecret = _totp.GenerateSecret();
        var code = new Totp(Base32Encoding.ToBytes(otherSecret)).ComputeTotp();

        Assert.False(_totp.VerifyCode(secret, code));
    }

    [Fact]
    public void A_code_well_outside_the_drift_window_is_rejected()
    {
        var secret = _totp.GenerateSecret();
        var totp = new Totp(Base32Encoding.ToBytes(secret));

        // Ten minutes in the past: far beyond the one-step tolerance.
        var stale = totp.ComputeTotp(DateTime.UtcNow.AddMinutes(-10));

        Assert.False(_totp.VerifyCode(secret, stale));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abcdef")]
    [InlineData("000000")]
    public void Malformed_codes_are_rejected_without_throwing(string code)
    {
        var secret = _totp.GenerateSecret();

        Assert.False(_totp.VerifyCode(secret, code));
    }

    [Fact]
    public void A_malformed_secret_is_rejected_without_throwing()
    {
        Assert.False(_totp.VerifyCode("not-valid-base32-!!!", "123456"));
    }

    [Fact]
    public void The_otpauth_uri_carries_the_issuer_and_the_secret()
    {
        var secret = _totp.GenerateSecret();
        var uri = _totp.BuildOtpAuthUri(secret, "ahmed@example.com");

        Assert.StartsWith("otpauth://totp/", uri);
        Assert.Contains($"secret={secret}", uri);
        Assert.Contains("issuer=SecureVault", uri);
        // The label contains an "@", which must be percent-encoded.
        Assert.Contains("ahmed%40example.com", uri);
    }
}
