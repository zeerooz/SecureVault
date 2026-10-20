namespace SecureVault.Api.Security;

public static class Base64Field
{
    /// <summary>
    /// Validates that a client-supplied string is base64 of an exact byte length.
    /// Length checks matter: they stop a client from storing a multi-megabyte
    /// "salt" and turning the KDF into a denial-of-service lever.
    /// </summary>
    public static bool TryDecodeExact(string? value, int expectedBytes, out byte[] bytes)
    {
        bytes = [];

        if (string.IsNullOrWhiteSpace(value) || value.Length > 1024)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[expectedBytes + 8];

        if (!Convert.TryFromBase64String(value, buffer, out var written) || written != expectedBytes)
        {
            return false;
        }

        bytes = buffer[..written].ToArray();
        return true;
    }
}
