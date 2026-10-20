using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureVault.Api.Data;
using SecureVault.Api.Domain;
using SecureVault.Api.Dtos;
using SecureVault.Api.Security;
using SecureVault.Api.Services;

namespace SecureVault.Api.Controllers;

[ApiController]
[Route("api/auth")]
[EnableRateLimiting(RateLimitPolicies.Authentication)]
public class AuthController(
    AppDbContext db,
    IPasswordHasher hasher,
    ITokenService tokens,
    ITotpService totp,
    ISecretProtector protector,
    IAuditService audit,
    IOptions<JwtOptions> jwtOptions,
    IOptions<LockoutOptions> lockoutOptions) : ControllerBase
{
    private const int AuthHashBytes = 32;
    private const int KdfSaltBytes = 16;
    private const int DefaultKdfIterations = 600_000;

    private readonly LockoutOptions _lockout = lockoutOptions.Value;

    /// <summary>
    /// Returns the KDF parameters the client needs before it can derive a master key.
    /// Unknown accounts get deterministic, plausible-looking parameters so this
    /// endpoint cannot be used to enumerate registered email addresses.
    /// </summary>
    [HttpPost("prelogin")]
    [ProducesResponseType<PreloginResponse>(StatusCodes.Status200OK)]
    public async Task<ActionResult<PreloginResponse>> Prelogin(PreloginRequest request, CancellationToken ct)
    {
        var email = Normalise(request.Email);
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == email, ct);

        if (user is not null)
        {
            return Ok(new PreloginResponse(
                user.KdfType, user.KdfIterations, Convert.ToBase64String(user.KdfSalt)));
        }

        return Ok(new PreloginResponse(
            KdfType.Pbkdf2Sha256, DefaultKdfIterations, Convert.ToBase64String(DecoySalt(email))));
    }

    [HttpPost("register")]
    [ProducesResponseType<LoginResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<LoginResponse>> Register(RegisterRequest request, CancellationToken ct)
    {
        var email = Normalise(request.Email);

        if (!Base64Field.TryDecodeExact(request.AuthHash, AuthHashBytes, out _))
        {
            return Problem("authHash must be base64 of exactly 32 bytes.", statusCode: StatusCodes.Status400BadRequest);
        }

        if (!Base64Field.TryDecodeExact(request.KdfSalt, KdfSaltBytes, out var kdfSalt))
        {
            return Problem("kdfSalt must be base64 of exactly 16 bytes.", statusCode: StatusCodes.Status400BadRequest);
        }

        if (await db.Users.AnyAsync(u => u.Email == email, ct))
        {
            // Registration unavoidably reveals that an address is taken. The
            // mitigation is the rate limiter on this route, not secrecy.
            return Problem("That email address is already registered.", statusCode: StatusCodes.Status409Conflict);
        }

        var (hash, salt) = hasher.Hash(request.AuthHash);

        var user = new User
        {
            Email = email,
            KdfType = KdfType.Pbkdf2Sha256,
            KdfIterations = request.KdfIterations,
            KdfSalt = kdfSalt,
            AuthHashVerifier = hash,
            AuthHashSalt = salt,
            ProtectedVaultKey = request.ProtectedVaultKey
        };

        db.Users.Add(user);
        audit.Record(AuditEvent.RegisterSucceeded, user.Id);
        await db.SaveChangesAsync(ct);

        var issued = await tokens.IssueAsync(user, ct);
        return Ok(ToLoginResponse(issued, user));
    }

    [HttpPost("login")]
    [ProducesResponseType<LoginResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var email = Normalise(request.Email);

        var user = await db.Users
            .Include(u => u.RecoveryCodes)
            .FirstOrDefaultAsync(u => u.Email == email, ct);

        if (user is null)
        {
            // Spend comparable effort on a non-existent account so response time
            // does not separate "no such user" from "wrong master password".
            hasher.Verify(request.AuthHash, DecoyVerifier, DecoySalt(email));
            audit.Record(AuditEvent.LoginFailed, null, "unknown account");
            await db.SaveChangesAsync(ct);
            return InvalidCredentials();
        }

        if (user.IsLockedOut)
        {
            audit.Record(AuditEvent.LoginLockedOut, user.Id);
            await db.SaveChangesAsync(ct);
            return InvalidCredentials();
        }

        if (!hasher.Verify(request.AuthHash, user.AuthHashVerifier, user.AuthHashSalt))
        {
            RegisterFailure(user);
            audit.Record(AuditEvent.LoginFailed, user.Id, "bad auth hash");
            await db.SaveChangesAsync(ct);
            return InvalidCredentials();
        }

        if (user.TwoFactorEnabled)
        {
            if (string.IsNullOrWhiteSpace(request.TwoFactorCode))
            {
                audit.Record(AuditEvent.TwoFactorChallenged, user.Id);
                await db.SaveChangesAsync(ct);
                return Ok(new TwoFactorRequiredResponse());
            }

            if (!VerifySecondFactor(user, request.TwoFactorCode))
            {
                RegisterFailure(user);
                audit.Record(AuditEvent.TwoFactorFailed, user.Id);
                await db.SaveChangesAsync(ct);
                return InvalidCredentials();
            }
        }

        user.FailedLoginCount = 0;
        user.LockoutEndsAt = null;
        audit.Record(AuditEvent.LoginSucceeded, user.Id);
        await db.SaveChangesAsync(ct);

        var issued = await tokens.IssueAsync(user, ct);
        return Ok(ToLoginResponse(issued, user));
    }

    [HttpPost("refresh")]
    [ProducesResponseType<RefreshResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken ct)
    {
        var issued = await tokens.RotateAsync(request.RefreshToken, ct);

        if (issued is null)
        {
            return Problem("The refresh token is invalid, expired or has already been used.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return Ok(new RefreshResponse(issued.AccessToken, issued.RefreshToken, issued.ExpiresInSeconds));
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout(RefreshRequest request, CancellationToken ct)
    {
        await tokens.RevokeAsync(request.RefreshToken, "logout", ct);
        audit.Record(AuditEvent.LoggedOut, GetUserId());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType<UserSummary>(StatusCodes.Status200OK)]
    public async Task<ActionResult<UserSummary>> Me(CancellationToken ct)
    {
        var id = GetUserId();
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct);

        return user is null
            ? NotFound()
            : Ok(new UserSummary(user.Id, user.Email, user.TwoFactorEnabled, user.CreatedAt));
    }

    // ---------------------------------------------------------------------

    private bool VerifySecondFactor(User user, string code)
    {
        if (protector.TryUnprotect(user.TotpSecretProtected, out var secret) && totp.VerifyCode(secret, code))
        {
            return true;
        }

        return TryConsumeRecoveryCode(user, code);
    }

    private bool TryConsumeRecoveryCode(User user, string code)
    {
        var normalised = code.Trim().Replace("-", string.Empty).ToUpperInvariant();
        var candidate = SHA256.HashData(Encoding.UTF8.GetBytes(normalised));

        var match = user.RecoveryCodes.FirstOrDefault(rc =>
            rc.UsedAt is null && CryptographicOperations.FixedTimeEquals(rc.CodeHash, candidate));

        if (match is null)
        {
            return false;
        }

        match.UsedAt = DateTime.UtcNow;
        audit.Record(AuditEvent.RecoveryCodeUsed, user.Id);
        return true;
    }

    private void RegisterFailure(User user)
    {
        user.FailedLoginCount++;

        if (user.FailedLoginCount >= _lockout.MaxFailedAttempts)
        {
            user.LockoutEndsAt = DateTime.UtcNow.AddMinutes(_lockout.LockoutMinutes);
            user.FailedLoginCount = 0;
        }
    }

    private IActionResult InvalidCredentials() =>
        Problem("Invalid credentials, or the account is temporarily locked after too many attempts.",
            statusCode: StatusCodes.Status401Unauthorized);

    private static LoginResponse ToLoginResponse(IssuedTokens issued, User user) =>
        new(issued.AccessToken,
            issued.RefreshToken,
            issued.ExpiresInSeconds,
            user.ProtectedVaultKey,
            new UserSummary(user.Id, user.Email, user.TwoFactorEnabled, user.CreatedAt));

    private Guid? GetUserId() =>
        Guid.TryParse(User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier), out var id)
            ? id
            : null;

    /// <summary>Stable per-email pseudo-salt, so a probing client sees a consistent answer.</summary>
    private byte[] DecoySalt(string email) =>
        HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(jwtOptions.Value.SigningKey),
            Encoding.UTF8.GetBytes("prelogin-decoy:" + email))[..KdfSaltBytes];

    private static byte[] DecoyVerifier { get; } = new byte[32];

    private static string Normalise(string email) => email.Trim().ToLowerInvariant();
}
