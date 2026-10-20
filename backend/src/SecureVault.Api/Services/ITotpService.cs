namespace SecureVault.Api.Services;

public interface ITotpService
{
    /// <summary>Generates a new base32 shared secret.</summary>
    string GenerateSecret();

    /// <summary>Builds the otpauth:// URI an authenticator app scans.</summary>
    string BuildOtpAuthUri(string secret, string email);

    /// <summary>Verifies a 6-digit code, allowing one step of clock drift either way.</summary>
    bool VerifyCode(string secret, string code);
}
