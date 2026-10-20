using Microsoft.EntityFrameworkCore;
using SecureVault.Api.Domain;

namespace SecureVault.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<VaultItem> VaultItems => Set<VaultItem>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Email).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.Email).IsUnique();
            e.Property(x => x.ProtectedVaultKey).HasMaxLength(1024).IsRequired();
            e.Property(x => x.TotpSecretProtected).HasMaxLength(1024);
            e.Property(x => x.KdfType).HasConversion<int>();

            e.HasMany(x => x.VaultItems).WithOne(x => x.User!).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(x => x.Sessions).WithOne(x => x.User!).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(x => x.RecoveryCodes).WithOne(x => x.User!).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<VaultItem>(e =>
        {
            e.HasKey(x => x.Id);
            // 32 KiB ceiling: generous for a note, small enough to bound abuse.
            e.Property(x => x.EncryptedData).HasMaxLength(32768).IsRequired();
            e.Property(x => x.Type).HasConversion<int>();
            e.HasIndex(x => new { x.UserId, x.UpdatedAt });
        });

        b.Entity<Session>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.RefreshTokenHash).IsRequired();
            e.HasIndex(x => x.RefreshTokenHash);
            e.HasIndex(x => x.FamilyId);
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.RevokedReason).HasMaxLength(128);
        });

        b.Entity<AuditLog>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Event).HasConversion<int>();
            e.Property(x => x.Detail).HasMaxLength(256);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.HasIndex(x => new { x.UserId, x.CreatedAt });
        });

        b.Entity<RecoveryCode>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.CodeHash).IsRequired();
            e.HasIndex(x => x.UserId);
        });
    }
}
