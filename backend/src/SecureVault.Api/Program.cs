using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using SecureVault.Api.Data;
using SecureVault.Api.Security;
using SecureVault.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
    .ValidateDataAnnotations()
    // Fail at startup rather than at the first login. A missing or short signing
    // key is a deployment mistake that must never degrade into a weak token.
    .ValidateOnStart();

builder.Services.AddOptions<LockoutOptions>()
    .Bind(builder.Configuration.GetSection(LockoutOptions.SectionName));

builder.Services.AddOptions<CorsOptions>()
    .Bind(builder.Configuration.GetSection(CorsOptions.SectionName));

var corsOrigins = builder.Configuration
    .GetSection(CorsOptions.SectionName)
    .Get<CorsOptions>()?.AllowedOrigins ?? [];

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

var connectionString = builder.Configuration.GetConnectionString("Postgres")
                       ?? "Host=localhost;Port=5432;Database=securevault;Username=securevault;Password=securevault";

builder.Services.AddDbContext<AppDbContext>(options => options.UseNpgsql(connectionString));

// Data-protection keys must outlive the container, otherwise every restart
// invalidates the stored TOTP secrets they protect.
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(
        builder.Configuration["DataProtection:KeyPath"] ?? "/var/securevault/keys"))
    .SetApplicationName("SecureVault");

// ---------------------------------------------------------------------------
// Application services
// ---------------------------------------------------------------------------

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IPasswordHasher, Argon2PasswordHasher>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<ITotpService, TotpService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<ICurrentUser, CurrentUser>();
builder.Services.AddScoped<ISecretProtector, DataProtectionSecretProtector>();

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

var signingKey = builder.Configuration[$"{JwtOptions.SectionName}:SigningKey"] ?? string.Empty;

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false; // keep "sub" and "sid" as-is
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration[$"{JwtOptions.SectionName}:Issuer"],
            ValidAudience = builder.Configuration[$"{JwtOptions.SectionName}:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                string.IsNullOrEmpty(signingKey) ? new string('0', 64) : signingKey)),
            // The default five-minute grace period quietly extends every token.
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = JwtRegisteredClaimNames.Sub
        };
    });

builder.Services.AddAuthorization();

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

var rateLimits = builder.Configuration
    .GetSection(RateLimitOptions.SectionName)
    .Get<RateLimitOptions>() ?? new RateLimitOptions();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy(RateLimitPolicies.Authentication, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ClientKey(context),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = rateLimits.AuthPermitPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.AddPolicy(RateLimitPolicies.Api, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ClientKey(context),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = rateLimits.ApiPermitPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.OnRejected = async (context, ct) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "60";
        await context.HttpContext.Response.WriteAsJsonAsync(new ProblemDetails
        {
            Status = StatusCodes.Status429TooManyRequests,
            Title = "Too many requests",
            Detail = "Slow down and try again in a minute."
        }, ct);
    };

    static string ClientKey(HttpContext context) =>
        context.User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
        ?? context.Connection.RemoteIpAddress?.ToString()
        ?? "unknown";
});

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
{
    if (corsOrigins.Length > 0)
    {
        policy.WithOrigins(corsOrigins).AllowAnyHeader().AllowAnyMethod();
    }
}));

builder.Services.AddControllers();
builder.Services.AddProblemDetails();
builder.Services.AddOpenApi();

builder.Services.AddHealthChecks().AddDbContextCheck<AppDbContext>();

var app = builder.Build();

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

app.UseExceptionHandler(handler => handler.Run(async context =>
{
    var feature = context.Features.Get<IExceptionHandlerFeature>();
    app.Logger.LogError(feature?.Error, "Unhandled exception on {Path}", context.Request.Path);

    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
    context.Response.ContentType = "application/problem+json";

    // Never echo exception text to the client: stack traces leak file paths,
    // library versions and sometimes connection strings.
    await context.Response.WriteAsJsonAsync(new ProblemDetails
    {
        Status = StatusCodes.Status500InternalServerError,
        Title = "Unexpected error",
        Detail = "The request could not be completed."
    });
}));

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers.XContentTypeOptions = "nosniff";
    headers.XFrameOptions = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()";
    // The API serves JSON only, so it needs no script, style or frame sources.
    headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
    headers["Cache-Control"] = "no-store";

    await next();
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options => options.WithTitle("SecureVault API"));
}
else
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health").AllowAnonymous();

await MigrateAsync(app);

app.Run();

static async Task MigrateAsync(WebApplication app)
{
    // Migrating on startup suits a single-instance demo deployment. With more
    // than one replica this belongs in a release step instead, or two instances
    // race each other applying the same migration.
    if (app.Configuration.GetValue("Database:MigrateOnStartup", true) is false)
    {
        return;
    }

    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    try
    {
        await db.Database.MigrateAsync();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Database migration failed on startup.");
        throw;
    }
}

/// <summary>Exposed so the integration tests can boot the real pipeline.</summary>
public partial class Program;
