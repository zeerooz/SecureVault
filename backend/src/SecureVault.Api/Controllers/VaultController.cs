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
/// Storage for opaque ciphertext. Nothing in this controller can read a vault
/// item; it moves base64 blobs in and out and enforces that a blob belongs to
/// the caller. Every query is scoped by the user id taken from the access
/// token, never from a route or body parameter.
/// </summary>
[ApiController]
[Route("api/vault/items")]
[Authorize]
[EnableRateLimiting(RateLimitPolicies.Api)]
public class VaultController(AppDbContext db, ICurrentUser currentUser, IAuditService audit) : ControllerBase
{
    private const int MaxItemsPerUser = 5000;

    [HttpGet]
    [ProducesResponseType<IReadOnlyList<VaultItemResponse>>(StatusCodes.Status200OK)]
    public async Task<ActionResult<IReadOnlyList<VaultItemResponse>>> GetAll(CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();

        var items = await db.VaultItems
            .AsNoTracking()
            .Where(i => i.UserId == userId)
            .OrderByDescending(i => i.UpdatedAt)
            .Select(i => new VaultItemResponse(i.Id, i.Type, i.EncryptedData, i.Revision, i.CreatedAt, i.UpdatedAt))
            .ToListAsync(ct);

        return Ok(items);
    }

    [HttpGet("{id:guid}")]
    [ProducesResponseType<VaultItemResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<VaultItemResponse>> GetById(Guid id, CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();

        var item = await db.VaultItems
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == id && i.UserId == userId, ct);

        // 404 rather than 403 for someone else's item: a 403 would confirm the
        // id exists, which is information the caller is not entitled to.
        return item is null ? NotFound() : Ok(ToResponse(item));
    }

    [HttpPost]
    [ProducesResponseType<VaultItemResponse>(StatusCodes.Status201Created)]
    public async Task<ActionResult<VaultItemResponse>> Create(CreateVaultItemRequest request, CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();

        if (!LooksLikeCiphertext(request.EncryptedData))
        {
            return Problem("encryptedData must be base64 and at least as long as an AES-GCM header.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var count = await db.VaultItems.CountAsync(i => i.UserId == userId, ct);

        if (count >= MaxItemsPerUser)
        {
            return Problem($"A vault is limited to {MaxItemsPerUser} items.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var item = new VaultItem
        {
            UserId = userId,
            Type = request.Type,
            EncryptedData = request.EncryptedData
        };

        db.VaultItems.Add(item);
        audit.Record(AuditEvent.VaultItemCreated, userId);
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(GetById), new { id = item.Id }, ToResponse(item));
    }

    [HttpPut("{id:guid}")]
    [ProducesResponseType<VaultItemResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<VaultItemResponse>> Update(Guid id, UpdateVaultItemRequest request, CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();

        if (!LooksLikeCiphertext(request.EncryptedData))
        {
            return Problem("encryptedData must be base64 and at least as long as an AES-GCM header.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var item = await db.VaultItems.FirstOrDefaultAsync(i => i.Id == id && i.UserId == userId, ct);

        if (item is null)
        {
            return NotFound();
        }

        if (item.Revision != request.Revision)
        {
            return Problem("This item changed in another session. Reload it before saving.",
                statusCode: StatusCodes.Status409Conflict);
        }

        item.Type = request.Type;
        item.EncryptedData = request.EncryptedData;
        item.Revision++;
        item.UpdatedAt = DateTime.UtcNow;

        audit.Record(AuditEvent.VaultItemUpdated, userId);
        await db.SaveChangesAsync(ct);

        return Ok(ToResponse(item));
    }

    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var userId = currentUser.RequireUserId();
        var item = await db.VaultItems.FirstOrDefaultAsync(i => i.Id == id && i.UserId == userId, ct);

        if (item is null)
        {
            return NotFound();
        }

        db.VaultItems.Remove(item);
        audit.Record(AuditEvent.VaultItemDeleted, userId);
        await db.SaveChangesAsync(ct);

        return NoContent();
    }

    private static VaultItemResponse ToResponse(VaultItem i) =>
        new(i.Id, i.Type, i.EncryptedData, i.Revision, i.CreatedAt, i.UpdatedAt);

    /// <summary>
    /// A shape check, not a security control. The server cannot verify that a
    /// blob decrypts; it can only reject input that is obviously not ciphertext.
    /// 28 bytes is the floor: a 12-byte IV plus a 16-byte GCM tag.
    /// </summary>
    private static bool LooksLikeCiphertext(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var buffer = new byte[value.Length];
        return Convert.TryFromBase64String(value, buffer, out var written) && written >= 28;
    }
}
