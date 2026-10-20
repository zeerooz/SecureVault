using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SecureVault.Api.Data;

namespace SecureVault.Tests.Integration;

/// <summary>
/// Boots the real application pipeline — real authentication, real rate
/// limiting, real controllers — against a throwaway SQLite database. Only the
/// database provider is swapped, so these tests exercise the middleware order
/// and authorization rules that unit tests cannot reach.
/// </summary>
public class SecureVaultFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly string _keyPath = Path.Combine(Path.GetTempPath(), "securevault-tests", Guid.NewGuid().ToString("N"));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.UseSetting("Jwt:SigningKey", "test-signing-key-at-least-32-characters-long-0123456789");
        builder.UseSetting("Jwt:Issuer", "securevault-tests");
        builder.UseSetting("Jwt:Audience", "securevault-tests");
        builder.UseSetting("DataProtection:KeyPath", _keyPath);

        // TestServer requests have no remote IP, so every test would share one
        // rate-limit partition. The limiter itself is still in the pipeline and
        // is covered by its own test, which lowers the limit deliberately.
        builder.UseSetting("RateLimits:AuthPermitPerMinute", "10000");
        builder.UseSetting("RateLimits:ApiPermitPerMinute", "10000");

        // The Npgsql migrations cannot be applied to SQLite; the schema is
        // created from the model instead, in InitializeAsync below.
        builder.UseSetting("Database:MigrateOnStartup", "false");

        builder.ConfigureServices(services =>
        {
            // AddDbContext registers more than DbContextOptions<T>: EF 10 also
            // adds an IDbContextOptionsConfiguration<T> that re-applies
            // UseNpgsql. Leaving it behind registers two providers at once,
            // which EF refuses to resolve. Strip every option registration tied
            // to this context before adding the SQLite one.
            var doomed = services
                .Where(d =>
                    d.ServiceType == typeof(AppDbContext) ||
                    (d.ServiceType.FullName?.Contains("DbContextOptions", StringComparison.Ordinal) ?? false))
                .ToList();

            foreach (var descriptor in doomed)
            {
                services.Remove(descriptor);
            }

            services.AddDbContext<AppDbContext>(options => options.UseSqlite(_connection));
        });
    }

    // Explicit implementations: xUnit's IAsyncLifetime uses Task, while
    // WebApplicationFactory already defines a ValueTask DisposeAsync. Keeping
    // them separate lets one type satisfy both contracts.
    async Task IAsyncLifetime.InitializeAsync()
    {
        Directory.CreateDirectory(_keyPath);

        // An in-memory SQLite database lives exactly as long as its connection,
        // so this one is opened for the lifetime of the fixture.
        await _connection.OpenAsync();

        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    Task IAsyncLifetime.DisposeAsync() => DisposeAsync().AsTask();

    public override async ValueTask DisposeAsync()
    {
        await _connection.DisposeAsync();
        await base.DisposeAsync();

        try
        {
            if (Directory.Exists(_keyPath))
            {
                Directory.Delete(_keyPath, recursive: true);
            }
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test run over.
        }
    }
}
