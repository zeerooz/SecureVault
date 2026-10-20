using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SecureVault.Api.Data;
using SecureVault.Api.Domain;
using SecureVault.Api.Dtos;
using SecureVault.Api.Security;
using SecureVault.Api.Services;

namespace SecureVault.Api.Controllers;

[ApiController]
[Route("api/account")]
[Authorize]
[EnableRateLimiting(RateLimitPolicies.Authentication)]
public class AccountController(
    AppDbContext db,
    ICurrentUser currentUser,
    ITotpService totp,
    ISecretProtector protector,
    IPasswordHasher hasher,
    IAuditService audit) : ControllerBase
{
    private const int RecoveryCodeCount = 8;

    /// <summary>
    /// Generates a candidate TOTP secret and stores it unconfirmed. Two-factor
    /// authentication is not switched on until the user proves they can produce
    /// a code from it, which prevents locking someone out of their own account
    /// with a secret their authenticator never actually received.
    /// </summary>
    [HttpPost("2fa/setup")]
    [ProducesResponseType<TwoFactorSetupResponse>(StatusCodes.Status200OK)]
    public async Task<ActionResult<TwoFactorSetupResponse>> SetupTwoFactor(CancellationToken ct)
    {
        var user = await RequireUserAsync(ct);

        if (user.TwoFactorEnabled)
        {
            return Problem("Two-factor authentication is already enabled.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var secret = totp.GenerateSecret();
        user.TotpSecretProtected = protector.Protect(secret);
        user.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        return Ok(new TwoFactorSetupResponse(secret, totp.BuildOtpAuthUri(secret, user.Email)));
    }

    [HttpPost("2fa/enable")]
    [ProducesResponseType<EnableTwoFactorResponse>(StatusCodes.Status200OK)]
    public async Task<ActionResult<EnableTwoFactorResponse>> EnableTwoFactor(
        EnableTwoFactorRequest request, CancellationToken ct)
    {
        var user = await RequireUserAsync(ct);

        if (!protector.TryUnprotect(user.TotpSecretProtected, out var secret))
        {
            return Problem("Start the setup step before enabling two-factor authentication.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (!totp.VerifyCode(secret, request.Code))
        {
            return Problem("That code is not valid. Check your authenticator clock and try again.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        user.TwoFactorEnabled = true;
        user.UpdatedAt = DateTime.UtcNow;

        // Replace any codes from a previous enrolment.
        db.RecoveryCodes.RemoveRange(db.RecoveryCodes.Where(rc => rc.UserId == user.Id));

        var plaintextCodes = new List<string>(RecoveryCodeCount);

        for (var i = 0; i < RecoveryCodeCount; i++)
        {
            var code = GenerateRecoveryCode();
            plaintextCodes.Add(code);

            db.RecoveryCodes.Add(new RecoveryCode
            {
                UserId = user.Id,
                CodeHash = HashRecoveryCode(code)
            });
        }

        audit.Record(AuditEvent.TwoFactorEnabled, user.Id);
        await db.SaveChangesAsync(ct);

        // The only time these are ever shown. We store hashes, so we could not
        // display them again even if we wanted to.
        return Ok(new EnableTwoFactorResponse(plaintextCodes));
    }

    [HttpPost("2fa/disable")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DisableTwoFactor(DisableTwoFactorRequest request, CancellationToken ct)
    {
        var user = await RequireUserAsync(ct);

        if (!user.TwoFactorEnabled)
        {
            return NoContent();
        }

        if (!protector.TryUnprotect(user.TotpSecretProtected, out var secret) || !totp.VerifyCode(secret, request.Code))
        {
            return Problem("A valid authenticator code is required to turn two-factor authentication off.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        user.TwoFactorEnabled = false;
        user.TotpSecretProtected = null;
        user.UpdatedAt = DateTime.UtcNow;
        db.RecoveryCodes.RemoveRange(db.RecoveryCodes.Where(rc => rc.UserId == user.Id));

        audit.Record(AuditEvent.TwoFactorDisabled, user.Id);
        await db.SaveChangesAsync(ct);

        return NoContent();
    }

    /// <summary>
    /// Changes the master password. The client re-derives its key, re-wraps the
    /// same vault key under it, and sends the new wrapper. Vault items are
    /// untouched: they are encrypted with the vault key, not with the master
    /// password, so none of them need re-encrypting.
    /// </summary>
    [HttpPost("master-password")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> ChangeMasterPassword(ChangeMasterPasswordRequest request, CancellationToken ct)
    {
        var user = await RequireUserAsync(ct);

        if (!hasher.Verify(request.CurrentAuthHash, user.AuthHashVerifier, user.AuthHashSalt))
        {
            return Problem("The current master password is incorrect.", statusCode: StatusCodes.Status400BadRequest);
        }

        if (!Base64Field.TryDecodeExact(request.NewAuthHash, 32, out _))
        {
            return Problem("newAuthHash must be base64 of exactly 32 bytes.", statusCode: StatusCodes.Status400BadRequest);
        }

        if (!Base64Field.TryDecodeExact(request.NewKdfSalt, 16, out var newSalt))
        {
            return Problem("newKdfSalt must be base64 of exactly 16 bytes.", statusCode: StatusCodes.Status400BadRequest);
        }

        var (hash, salt) = hasher.Hash(request.NewAuthHash);

        user.AuthHashVerifier = hash;
        user.AuthHashSalt = salt;
        user.KdfSalt = newSalt;
        user.KdfIterations = request.NewKdfIterations;
        user.ProtectedVaultKey = request.NewProtectedVaultKey;
        user.UpdatedAt = DateTime.UtcNow;

        // Changing the master password invalidates every existing session: if
        // the reason for the change is a suspected compromise, leaving old
        // refresh tokens alive would defeat the point.
        var now = DateTime.UtcNow;

        await db.Sessions
            .Where(s => s.UserId == user.Id && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, "master password changed"), ct);

        audit.Record(AuditEvent.MasterPasswordChanged, user.Id);
        await db.SaveChangesAsync(ct);

        return NoContent();
    }

    private async Task<User> RequireUserAsync(CancellationToken ct)
    {
        var id = currentUser.RequireUserId();
        return await db.Users.FirstAsync(u => u.Id == id, ct);
    }

    /// <summary>Ten characters from an unambiguous alphabet, formatted as XXXXX-XXXXX.</summary>
    private static string GenerateRecoveryCode()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var chars = new char[10];

        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        return string.Concat(new string(chars, 0, 5), "-", new string(chars, 5, 5));
    }

    private static byte[] HashRecoveryCode(string code) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(code.Replace("-", string.Empty).ToUpperInvariant()));
}
