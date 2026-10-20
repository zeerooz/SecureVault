using System.Net;
using System.Net.Http.Json;
using SecureVault.Api.Domain;
using SecureVault.Api.Dtos;

namespace SecureVault.Tests.Integration;

public class VaultEndpointTests(SecureVaultFactory factory) : IClassFixture<SecureVaultFactory>
{
    [Fact]
    public async Task Vault_routes_reject_anonymous_callers()
    {
        var client = factory.CreateClient();

        var response = await client.GetAsync("/api/vault/items");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_item_can_be_created_read_updated_and_deleted()
    {
        var client = await AuthenticatedClientAsync();
        var ciphertext = TestClient.FakeCiphertext();

        var created = await client.PostAsJsonAsync("/api/vault/items",
            new CreateVaultItemRequest { Type = VaultItemType.Login, EncryptedData = ciphertext });

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var item = await created.Content.ReadFromJsonAsync<VaultItemResponse>();

        Assert.Equal(ciphertext, item!.EncryptedData);
        Assert.Equal(1, item.Revision);

        var fetched = await client.GetFromJsonAsync<VaultItemResponse>($"/api/vault/items/{item.Id}");
        Assert.Equal(ciphertext, fetched!.EncryptedData);

        var newCiphertext = TestClient.FakeCiphertext(128);
        var updated = await client.PutAsJsonAsync($"/api/vault/items/{item.Id}",
            new UpdateVaultItemRequest
            {
                Type = VaultItemType.SecureNote,
                EncryptedData = newCiphertext,
                Revision = item.Revision
            });

        updated.EnsureSuccessStatusCode();
        var updatedItem = await updated.Content.ReadFromJsonAsync<VaultItemResponse>();

        Assert.Equal(newCiphertext, updatedItem!.EncryptedData);
        Assert.Equal(2, updatedItem.Revision);
        Assert.Equal(VaultItemType.SecureNote, updatedItem.Type);

        var deleted = await client.DeleteAsync($"/api/vault/items/{item.Id}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        var afterDelete = await client.GetAsync($"/api/vault/items/{item.Id}");
        Assert.Equal(HttpStatusCode.NotFound, afterDelete.StatusCode);
    }

    [Fact]
    public async Task A_stale_revision_is_rejected_instead_of_overwriting()
    {
        var client = await AuthenticatedClientAsync();

        var created = await client.PostAsJsonAsync("/api/vault/items",
            new CreateVaultItemRequest { EncryptedData = TestClient.FakeCiphertext() });
        var item = await created.Content.ReadFromJsonAsync<VaultItemResponse>();

        var firstWrite = await client.PutAsJsonAsync($"/api/vault/items/{item!.Id}",
            new UpdateVaultItemRequest { EncryptedData = TestClient.FakeCiphertext(), Revision = 1 });
        firstWrite.EnsureSuccessStatusCode();

        // A second tab still believes it is on revision 1.
        var secondWrite = await client.PutAsJsonAsync($"/api/vault/items/{item.Id}",
            new UpdateVaultItemRequest { EncryptedData = TestClient.FakeCiphertext(), Revision = 1 });

        Assert.Equal(HttpStatusCode.Conflict, secondWrite.StatusCode);
    }

    [Fact]
    public async Task One_user_cannot_read_another_users_item()
    {
        var owner = await AuthenticatedClientAsync();

        var created = await owner.PostAsJsonAsync("/api/vault/items",
            new CreateVaultItemRequest { EncryptedData = TestClient.FakeCiphertext() });
        var item = await created.Content.ReadFromJsonAsync<VaultItemResponse>();

        var attacker = await AuthenticatedClientAsync();

        var read = await attacker.GetAsync($"/api/vault/items/{item!.Id}");
        var update = await attacker.PutAsJsonAsync($"/api/vault/items/{item.Id}",
            new UpdateVaultItemRequest { EncryptedData = TestClient.FakeCiphertext(), Revision = 1 });
        var delete = await attacker.DeleteAsync($"/api/vault/items/{item.Id}");

        // 404, never 403: a 403 would confirm that the id is real.
        Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
    }

    [Fact]
    public async Task The_list_endpoint_only_returns_the_callers_own_items()
    {
        var first = await AuthenticatedClientAsync();
        await first.PostAsJsonAsync("/api/vault/items",
            new CreateVaultItemRequest { EncryptedData = TestClient.FakeCiphertext() });

        var second = await AuthenticatedClientAsync();
        var secondCiphertext = TestClient.FakeCiphertext();
        await second.PostAsJsonAsync("/api/vault/items",
            new CreateVaultItemRequest { EncryptedData = secondCiphertext });

        var items = await second.GetFromJsonAsync<List<VaultItemResponse>>("/api/vault/items");

        Assert.Single(items!);
        Assert.Equal(secondCiphertext, items![0].EncryptedData);
    }

    [Fact]
    public async Task Data_that_is_not_plausible_ciphertext_is_rejected()
    {
        var client = await AuthenticatedClientAsync();

        var response = await client.PostAsJsonAsync("/api/vault/items",
            new CreateVaultItemRequest { EncryptedData = "this is obviously plaintext" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Too_short_a_blob_cannot_hold_an_iv_and_a_tag()
    {
        var client = await AuthenticatedClientAsync();

        var response = await client.PostAsJsonAsync("/api/vault/items",
            new CreateVaultItemRequest { EncryptedData = Convert.ToBase64String(new byte[16]) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private async Task<HttpClient> AuthenticatedClientAsync()
    {
        var client = factory.CreateClient();
        var (session, _) = await client.RegisterAsync();
        client.Authenticate(session.AccessToken);
        return client;
    }
}
