using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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

/// <summary>
/// Lets a user see where they are signed in and cut off anything they do not
/// recognise. This is the practical answer to "someone has my laptop".
/// </summary>
[ApiController]
[Route("api/sessions")]
[Authorize]
[EnableRateLimiting(RateLimitPolicies.Api)]
public class SessionsController(AppDbContext db, ICurrentUser currentUser, IAuditService audit) : ControllerBase
{
    [HttpGet]
    [ProducesResponseType<IReadOnlyList<SessionResponse>>(StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<SessionResponse>>> GetAll(CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();
        var currentSessionId = GetCurrentSessionId();
        var now = DateTime.UtcNow;

        var sessions = await db.Sessions
            .AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderByDescending(s => s.LastSeenAt)
            .ToListAsync(ct);

        return Ok(sessions
            .Select(s => new SessionResponse(
                s.Id, s.IpAddress, s.UserAgent, s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.Id == currentSessionId))
            .ToList());
    }

    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Revoke(Guid id, CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.Id == id && s.UserId == userId, ct);

        if (session is null)
        {
            return NotFound();
        }

        if (session.RevokedAt is null)
        {
            session.RevokedAt = DateTime.UtcNow;
            session.RevokedReason = "revoked by user";
            audit.Record(AuditEvent.SessionRevoked, userId);
            await db.SaveChangesAsync(ct);
        }

        return NoContent();
    }

    /// <summary>Signs out everywhere except the device making the request.</summary>
    [HttpDelete("others")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RevokeOthers(CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();
        var currentSessionId = GetCurrentSessionId();
        var now = DateTime.UtcNow;

        await db.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.Id != currentSessionId)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAt, now)
                .SetProperty(x => x.RevokedReason, "revoked by user"), ct);

        audit.Record(AuditEvent.SessionRevoked, userId, "all other sessions");
        await db.SaveChangesAsync(ct);

        return NoContent();
    }

    private Guid GetCurrentSessionId() =>
        Guid.TryParse(User.FindFirstValue(JwtRegisteredClaimNames.Sid)
                      ?? User.FindFirstValue(ClaimTypes.Sid), out var id)
            ? id
            : Guid.Empty;
}
