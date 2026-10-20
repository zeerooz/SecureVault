using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SecureVault.Api.Services;

public class CurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    public Guid? UserId
    {
        get
        {
            var value = accessor.HttpContext?.User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                        ?? accessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);

            return Guid.TryParse(value, out var id) ? id : null;
        }
    }

    public Guid RequireUserId() =>
        UserId ?? throw new InvalidOperationException("No authenticated user on the current request.");
}
