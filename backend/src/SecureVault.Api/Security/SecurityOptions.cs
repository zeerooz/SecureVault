using System.ComponentModel.DataAnnotations;

namespace SecureVault.Api.Security;

public class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required, MinLength(32)]
    public string SigningKey { get; set; } = string.Empty;

    [Required] public string Issuer { get; set; } = "securevault";
    [Required] public string Audience { get; set; } = "securevault-web";

    /// <summary>Short on purpose: a stolen access token should expire fast.</summary>
    public int AccessTokenMinutes { get; set; } = 15;

    public int RefreshTokenDays { get; set; } = 14;
}

public class LockoutOptions
{
    public const string SectionName = "Lockout";

    public int MaxFailedAttempts { get; set; } = 8;
    public int LockoutMinutes { get; set; } = 15;
}

public class CorsOptions
{
    public const string SectionName = "Cors";
    public string[] AllowedOrigins { get; set; } = [];
}

public class RateLimitOptions
{
    public const string SectionName = "RateLimits";

    /// <summary>Requests per minute against credential-handling routes, per client.</summary>
    public int AuthPermitPerMinute { get; set; } = 10;

    /// <summary>Requests per minute against authenticated vault routes, per client.</summary>
    public int ApiPermitPerMinute { get; set; } = 300;
}
