using SecureVault.Api.Data;
using SecureVault.Api.Domain;

namespace SecureVault.Api.Services;

public class AuditService(AppDbContext db, IHttpContextAccessor accessor) : IAuditService
{
    public void Record(AuditEvent auditEvent, Guid? userId, string? detail = null)
    {
        var http = accessor.HttpContext;

        db.AuditLogs.Add(new AuditLog
        {
            Event = auditEvent,
            UserId = userId,
            Detail = Truncate(detail, 256),
            IpAddress = Truncate(http?.Connection.RemoteIpAddress?.ToString(), 64),
            UserAgent = Truncate(http?.Request.Headers.UserAgent.ToString(), 512)
        });
    }

    private static string? Truncate(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length <= max ? value : value[..max];
}
