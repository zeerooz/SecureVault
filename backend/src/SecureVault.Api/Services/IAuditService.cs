using SecureVault.Api.Domain;

namespace SecureVault.Api.Services;

public interface IAuditService
{
    /// <summary>Queues an audit row. The caller is responsible for SaveChanges.</summary>
    void Record(AuditEvent auditEvent, Guid? userId, string? detail = null);
}
