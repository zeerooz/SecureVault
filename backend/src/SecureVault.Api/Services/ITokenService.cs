using SecureVault.Api.Domain;

namespace SecureVault.Api.Services;

public record IssuedTokens(string AccessToken, string RefreshToken, int ExpiresInSeconds);

public interface ITokenService
{
    /// <summary>Issues an access token plus a brand-new refresh-token family.</summary>
    Task<IssuedTokens> IssueAsync(User user, CancellationToken ct = default);

    /// <summary>
    /// Rotates a refresh token. Returns null when the token is unknown, expired
    /// or already revoked; reuse of a revoked token kills the whole family.
    /// </summary>
    Task<IssuedTokens?> RotateAsync(string refreshToken, CancellationToken ct = default);

    Task RevokeAsync(string refreshToken, string reason, CancellationToken ct = default);

    /// <summary>SHA-256 of the raw token, which is all we ever persist.</summary>
    byte[] HashToken(string refreshToken);
}
