using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureVault.Api.Data;
using SecureVault.Api.Domain;
using SecureVault.Api.Security;

namespace SecureVault.Api.Services;

public class TokenService(
    AppDbContext db,
    IOptions<JwtOptions> jwtOptions,
    IHttpContextAccessor accessor,
    IAuditService audit,
    ILogger<TokenService> logger) : ITokenService
{
    private readonly JwtOptions _jwt = jwtOptions.Value;

    public async Task<IssuedTokens> IssueAsync(User user, CancellationToken ct = default)
    {
        var tokens = await CreateSessionAsync(user.Id, Guid.NewGuid(), ct);
        return tokens;
    }

    public async Task<IssuedTokens?> RotateAsync(string refreshToken, CancellationToken ct = default)
    {
        var hash = HashToken(refreshToken);

        var session = await db.Sessions
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.RefreshTokenHash == hash, ct);

        if (session?.User is null)
        {
            return null;
        }

        // Reuse detection. A refresh token is single-use; seeing a revoked one
        // again means either a replay or a stolen token, and we cannot tell
        // which. The safe response is to burn the entire family so both the
        // attacker and the victim are forced to re-authenticate.
        if (session.RevokedAt is not null)
        {
            logger.LogWarning("Refresh token reuse detected for user {UserId}, family {FamilyId}",
                session.UserId, session.FamilyId);

            await RevokeFamilyAsync(session.FamilyId, "token reuse detected", ct);
            audit.Record(AuditEvent.TokenReuseDetected, session.UserId);
            await db.SaveChangesAsync(ct);
            return null;
        }

        if (session.ExpiresAt <= DateTime.UtcNow)
        {
            return null;
        }

        session.RevokedAt = DateTime.UtcNow;
        session.RevokedReason = "rotated";

        var issued = await CreateSessionAsync(session.UserId, session.FamilyId, ct);
        audit.Record(AuditEvent.TokenRefreshed, session.UserId);
        await db.SaveChangesAsync(ct);

        return issued;
    }

    public async Task RevokeAsync(string refreshToken, string reason, CancellationToken ct = default)
    {
        var hash = HashToken(refreshToken);
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.RefreshTokenHash == hash, ct);

        if (session is null || session.RevokedAt is not null)
        {
            return;
        }

        session.RevokedAt = DateTime.UtcNow;
        session.RevokedReason = reason;
        await db.SaveChangesAsync(ct);
    }

    public byte[] HashToken(string refreshToken) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken));

    private async Task<IssuedTokens> CreateSessionAsync(Guid userId, Guid familyId, CancellationToken ct)
    {
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);

        var refreshToken = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(64));
        var http = accessor.HttpContext;

        var session = new Session
        {
            UserId = userId,
            FamilyId = familyId,
            RefreshTokenHash = HashToken(refreshToken),
            ExpiresAt = DateTime.UtcNow.AddDays(_jwt.RefreshTokenDays),
            IpAddress = http?.Connection.RemoteIpAddress?.ToString(),
            UserAgent = Truncate(http?.Request.Headers.UserAgent.ToString(), 512)
        };

        db.Sessions.Add(session);
        await db.SaveChangesAsync(ct);

        return new IssuedTokens(CreateAccessToken(user, session.Id), refreshToken, _jwt.AccessTokenMinutes * 60);
    }

    private async Task RevokeFamilyAsync(Guid familyId, string reason, CancellationToken ct)
    {
        var now = DateTime.UtcNow;

        await db.Sessions
            .Where(s => s.FamilyId == familyId && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, reason), ct);
    }

    private string CreateAccessToken(User user, Guid sessionId)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SigningKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        Claim[] claims =
        [
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            // Lets the client tell which row in its session list is itself.
            new(JwtRegisteredClaimNames.Sid, sessionId.ToString()),
            new("twofactor", user.TwoFactorEnabled ? "true" : "false")
        ];

        var token = new JwtSecurityToken(
            issuer: _jwt.Issuer,
            audience: _jwt.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(_jwt.AccessTokenMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string? Truncate(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length <= max ? value : value[..max];
}
