namespace SecureVault.Api.Services;

public interface ICurrentUser
{
    Guid? UserId { get; }
    Guid RequireUserId();
}
