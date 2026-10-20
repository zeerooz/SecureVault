namespace SecureVault.Api.Security;

public static class RateLimitPolicies
{
    /// <summary>
    /// Applied to every unauthenticated credential-handling route. Argon2id is
    /// deliberately expensive, so an unthrottled login endpoint is both a
    /// guessing oracle and a cheap way to exhaust server CPU.
    /// </summary>
    public const string Authentication = "authentication";

    /// <summary>Looser limit for authenticated vault traffic.</summary>
    public const string Api = "api";
}
