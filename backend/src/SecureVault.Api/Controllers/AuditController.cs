using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SecureVault.Api.Data;
using SecureVault.Api.Dtos;
using SecureVault.Api.Security;
using SecureVault.Api.Services;

namespace SecureVault.Api.Controllers;

[ApiController]
[Route("api/audit")]
[Authorize]
[EnableRateLimiting(RateLimitPolicies.Api)]
public class AuditController(AppDbContext db, ICurrentUser currentUser) : ControllerBase
{
    private const int MaxPageSize = 100;

    /// <summary>
    /// The user's own security timeline. A failed login they did not make is
    /// the earliest signal they have that someone is guessing their password.
    /// </summary>
    [HttpGet]
    [ProducesResponseType<IReadOnlyList<AuditLogResponse>>(StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<AuditLogResponse>>> GetAll(
        [FromQuery] int take = 50, CancellationToken ct = default)
    {
        var userId = currentUser.RequireUserId();
        var pageSize = Math.Clamp(take, 1, MaxPageSize);

        var entries = await db.AuditLogs
            .AsNoTracking()
            .Where(a => a.UserId == userId)
            .OrderByDescending(a => a.Id)
            .Take(pageSize)
            .Select(a => new AuditLogResponse(a.Id, a.Event.ToString(), a.Detail, a.IpAddress, a.CreatedAt))
            .ToListAsync(ct);

        return Ok(entries);
    }
}
