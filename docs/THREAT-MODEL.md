# Threat model

This document states plainly what SecureVault protects, what it does not, and what an
attacker actually gets in each scenario. Where the design has a weakness, it is written
down rather than left for a reader to find.

---

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| Vault item contents | Passwords, usernames, notes. The whole point. |
| Master password | Unlocks everything; also the one unrecoverable secret. |
| Vault key | The AES-256 key every item is encrypted with. |
| Session tokens | Bearer credentials for the API. |
| Account metadata | Email, item count, activity times. Lower value, still leaks. |

## 2. Who the attackers are

| # | Attacker | Capability assumed |
|---|---|---|
| **A1** | Database thief | A dump of the PostgreSQL database — SQL injection, a leaked backup, a stolen disk. |
| **A2** | Malicious or compromised server operator | Full control of the running API, able to read memory and change responses. |
| **A3** | Network attacker | Can observe, and with a mis-issued certificate modify, traffic in flight. |
| **A4** | Online guesser | No prior access; can only make API requests. |
| **A5** | Attacker with a stolen session token | Has an access or refresh token, but not the master password. |
| **A6** | Attacker with XSS on the web origin | Can run JavaScript in a logged-in user's browser. |
| **A7** | Attacker with the unlocked device | Physical access while the vault is open. |

## 3. Trust boundary

The boundary runs **between the browser and the network**. Everything on the server side
is untrusted by design.

```
 TRUSTED                        │  UNTRUSTED
                                │
 master password                │  API server
 master key    (PBKDF2)         │  PostgreSQL
 vault key     (AES-256)        │  backups, logs, hosting provider
 plaintext items                │  network path
                                │
         ── only ciphertext and an auth hash cross this line ──
```

## 4. The cryptography, concretely

All of this runs in the browser, in [`frontend/src/crypto/`](../frontend/src/crypto).

```
masterKey   = PBKDF2-SHA256(masterPassword, kdfSalt, 600_000 iterations)   → 32 bytes
authHash    = PBKDF2-SHA256(masterKey, masterPassword, 1 iteration)        → 32 bytes
wrappingKey = HKDF-SHA256(masterKey, info = "securevault:vault-key-wrap:v1")
vaultKey    = 32 random bytes from the CSPRNG
```

- `authHash` is the **only** derived value sent to the server. The server stores
  `Argon2id(authHash)` — m = 19 MiB, t = 2, p = 1, with a 16-byte random salt.
- `vaultKey` is encrypted under `wrappingKey` with AES-256-GCM and stored as
  `protectedVaultKey`. The server treats it as an opaque string.
- Each item is encrypted with `vaultKey` under AES-256-GCM, with a fresh 12-byte random
  IV per encryption. Stored layout is `base64(IV ‖ ciphertext ‖ tag)`.

**Why the indirection through a vault key?** Changing the master password re-wraps 32
bytes instead of re-encrypting every item. It also means a master password change cannot
corrupt the vault halfway through.

**Why PBKDF2 in the browser and Argon2id on the server?** PBKDF2 is native to WebCrypto,
so it runs as compiled code with no WASM download; a pure-JS Argon2 would be slower per
iteration and therefore *weaker* at the same wall-clock cost. Memory-hardness is applied
where it actually defends against offline cracking — the server-side verifier.

**Why `wrappingKey` is non-extractable.** It is imported with `extractable: false`, so
even code running on the page cannot read its bytes back out of the browser.

---

## 5. What each attacker gets

### A1 — Attacker with the full database

**Gets:** email addresses, account creation and update times, KDF salts and iteration
counts, `Argon2id(authHash)` and its salt, `protectedVaultKey`, every item's ciphertext,
item type, size, revision count and timestamps, IP addresses and user agents from the
audit log and session table, SHA-256 hashes of recovery codes, and the
DataProtection-encrypted TOTP secrets.

**Does not get:** any item's contents, any password, the vault key, or the master
password.

**What they can attempt:** an offline guess against `Argon2id(authHash)`. Each guess
costs one PBKDF2 run of 600,000 iterations *plus* one Argon2id computation at 19 MiB.
A correct guess yields the master password, and from it the vault.

This is the honest bottom line: **a database leak reduces to the strength of each
individual master password.** A 12-character random password is far out of reach; the
word `password123` falls immediately. This is why registration enforces a minimum length
and shows an entropy estimate, and it is the reason the product cannot promise safety for
a weak master password.

**What they also learn, which is not nothing:** who has an account, how many items each
person holds, roughly how large each item is, and when each was last touched. Item names
are *not* visible — they live inside the ciphertext.

### A2 — Malicious or compromised server operator

**Gets:** everything in A1, plus live traffic, plus the ability to change what the server
returns.

**Cannot:** read a vault at rest. But this attacker has a real attack the cryptography
does not stop:

> **The server ships the client.** A malicious server can serve modified JavaScript that
> captures the master password as it is typed. No amount of client-side encryption
> defends against this, because the attacker controls the thing doing the encrypting.

This is an inherent limit of every browser-delivered zero-knowledge product, including
the commercial ones. It is mitigated in practice by a strict Content-Security-Policy,
Subresource Integrity, reproducible builds and published hashes — and properly solved
only by a client the server does not deliver, such as a native app or an extension.
**SecureVault ships a CSP and nothing further, so a hostile operator wins.** Stated
plainly because it is the single biggest limitation of the design.

A lesser attack also exists: the server could answer `prelogin` with a very low iteration
count to weaken derivation. The client rejects anything under 100,000 iterations, which
closes that one.

### A3 — Network attacker

**Gets:** with plain TLS, nothing of value — only ciphertext and an auth hash cross the
wire, and the auth hash is useless without surviving the server's Argon2id verifier.

**With a mis-issued certificate** they become A2, with all that implies. HSTS is enabled
in production to prevent downgrade.

### A4 — Online guesser

**Blocked by three independent controls:**

1. A fixed-window rate limit of 10 requests per minute per client on every credential
   route.
2. Account lockout after 8 consecutive failures, for 15 minutes.
3. Argon2id at 19 MiB per attempt, which bounds how fast the server itself can be made to
   check guesses.

**Cannot determine whether an email is registered.** `prelogin` returns deterministic
decoy KDF parameters, derived as `HMAC-SHA256(serverKey, "prelogin-decoy:" + email)`, for
unknown accounts — so the same unknown address always gets the same plausible answer.
Failed logins return byte-identical responses whether or not the account exists, and
non-existent accounts still pay the cost of a hash computation so timing does not
separate the two cases.

**Known gap:** registration returns `409 Conflict` for an address already in use, which
does disclose membership. Avoiding it entirely requires email-confirmation flows that
this project does not implement. The rate limiter is the only mitigation, and that is a
deliberate, documented trade rather than an oversight.

### A5 — Attacker with a stolen session token

**Gets:** the ability to list, create, modify and delete *ciphertext*. They can destroy a
vault. They **cannot read a single item**, because the vault key is derived from the
master password and never sent to the server.

**Limits on the window:**

- Access tokens expire in 15 minutes, with clock skew tightened to 30 seconds from the
  five-minute default.
- Refresh tokens are single-use. Rotation is enforced, and replay of an already-rotated
  token revokes the **entire token family** — so a stolen refresh token stops working as
  soon as the real user refreshes, and vice versa. Either way the theft surfaces.
- Only SHA-256 hashes of refresh tokens are stored, so A1 cannot mint sessions.
- The user can see every active session with its IP and user agent, and revoke any of
  them.
- Changing the master password revokes every session.

### A6 — Attacker with XSS on the web origin

**Gets:** effectively everything, while the vault is unlocked. Injected script can read
the decrypted vault out of the page and exfiltrate it.

**What the design does to limit this:**

- Tokens live in JavaScript module scope, never in `localStorage` or `sessionStorage`, so
  there is no persistent credential to steal and no takeover that survives the tab.
- The vault key is never persisted, so a reload genuinely re-locks the vault.
- `wrappingKey` is non-extractable, so the key that unwraps the vault cannot be read out
  directly.
- A strict CSP restricts `connect-src` to this origin and the HIBP range API, which
  constrains where data could be sent.
- React escapes interpolated content by default, and the app uses no
  `dangerouslySetInnerHTML`.

**Honest assessment:** these raise the cost and shrink the window; they do not stop a
determined attacker who already runs code on the page. XSS prevention is the actual
control, and it has to hold.

### A7 — Attacker with the unlocked device

**Gets:** the vault. Nothing in this design defends an unlocked, logged-in session.

Mitigations are limited to reducing exposure: revealed secrets re-hide after 20 seconds,
the vault locks on reload, and sessions can be revoked remotely from another device. An
idle auto-lock timer is a known gap, listed in section 8.

---

## 6. Things that are deliberately *not* zero-knowledge

Stated separately so they are not mistaken for oversights.

| Item | Why the server must see it | How it is protected |
|---|---|---|
| Email address | Needed to identify an account and fetch KDF parameters. | Stored in plaintext. |
| TOTP shared secret | The server has to verify codes, so it must be able to read the secret. | Encrypted at rest with ASP.NET Data Protection. An attacker holding both the database **and** the key ring recovers it. |
| Item type | Lets the client render a list without decrypting everything first. | Plaintext column; reveals a category, never a value. |
| Timestamps, sizes, counts | Inherent to storing rows at all. | Not protected. See A1. |

Two-factor authentication protects the **account**, not the **data**. A TOTP code cannot
decrypt anything; it only gates the issuing of session tokens.

## 7. Deliberate omissions

- **Shared vaults.** Sharing requires key exchange between users, which is where
  zero-knowledge designs most often break. Shipping it badly would be worse than not
  shipping it. Doing it properly means per-user keypairs and wrapping the vault key to a
  recipient's public key.
- **Password reset.** There is no recovery path, and there cannot be one: the server
  holds no key. An email-based reset would mean the server could decrypt vaults, which
  would make every claim in this document false.
- **Encrypted item names.** Names are inside the ciphertext, which is why search runs
  client-side over the whole decrypted vault. The cost is that the entire vault is
  fetched on unlock; that cost is accepted.

## 8. Known gaps and what would close them

| Gap | Impact | Fix |
|---|---|---|
| Server ships the client (A2) | A hostile operator defeats the entire model | Subresource Integrity, reproducible builds with published hashes, a browser extension or native client |
| No idle auto-lock | An unattended unlocked tab stays unlocked | Lock on an inactivity timer and on tab visibility loss |
| Registration discloses membership | Email enumeration via `409` | Email-confirmation registration flow |
| Rate limiting is per-process and in memory | Multiple API replicas each allow the full quota | Move the limiter to Redis |
| No audit-log integrity protection | An attacker with database write access can erase their traces | Append-only storage, or hash-chained entries |
| Argon2id runs inline on the request thread | A burst of logins is a CPU denial-of-service lever | A work queue, or a proof-of-work challenge before hashing |
| No breach-forcing password policy | A user can still choose a weak master password | Check the master password against HIBP at registration and refuse known-breached ones |

## 9. How to verify the claims here

The interesting assertions are covered by tests rather than asserted on trust:

```bash
# The server never receives anything it could decrypt
cd backend && dotnet test --filter "FullyQualifiedName~AuthEndpointTests"

# Token replay revokes the family; cross-user access returns 404
cd backend && dotnet test --filter "FullyQualifiedName~SessionLifecycleTests|FullyQualifiedName~VaultEndpointTests"

# Encryption round-trips, rejects tampering, and leaks no plaintext
cd frontend && npm run test
```

To see what the server actually holds, open the database and look:

```sql
SELECT "Email", "KdfIterations", encode("AuthHashVerifier", 'hex'), "ProtectedVaultKey" FROM "Users";
SELECT "Type", "EncryptedData", "UpdatedAt" FROM "VaultItems";
```

Every value is either a hash, a salt, or base64 ciphertext.
