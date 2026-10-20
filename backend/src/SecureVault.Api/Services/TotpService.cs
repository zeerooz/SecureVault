using System.Security.Cryptography;
using OtpNet;

namespace SecureVault.Api.Services;

public class TotpService : ITotpService
{
    private const string Issuer = "SecureVault";

    public string GenerateSecret() => Base32Encoding.ToString(RandomNumberGenerator.GetBytes(20));

    public string BuildOtpAuthUri(string secret, string email)
    {
        var label = Uri.EscapeDataString($"{Issuer}:{email}");
        var issuer = Uri.EscapeDataString(Issuer);
        return $"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
    }

    public bool VerifyCode(string secret, string code)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        byte[] key;
        try
        {
            key = Base32Encoding.ToBytes(secret);
        }
        catch (ArgumentException)
        {
            return false;
        }

        var totp = new Totp(key);

        // VerificationWindow(1, 1) tolerates one 30s step of drift in each
        // direction. Wider would be friendlier and weaker; this is the usual
        // compromise and it is what RFC 6238 section 5.2 suggests.
        return totp.VerifyTotp(code.Trim(), out _, new VerificationWindow(previous: 1, future: 1));
    }
}
