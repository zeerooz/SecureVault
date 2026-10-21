# SecureVault

A password manager where the server cannot read your passwords — not "does not", *cannot*.
Everything is encrypted in the browser with AES-256-GCM before it is sent, under a key
derived from a master password that never leaves the device.

**[Threat model](docs/THREAT-MODEL.md)** — what an attacker actually gets if the database
leaks, who this defends against, and where the design loses. It is the most useful file
in this repository.

```
ASP.NET Core 10  ·  React 19 + TypeScript  ·  PostgreSQL 18  ·  Docker  ·  74 tests
```

---

## The claim, and how to check it yourself

Everything below runs against a real stack. Nothing is asserted on trust.

```bash
git clone https://github.com/<your-username>/SecureVault.git
cd SecureVault

cp .env.example .env
# Generate a signing key — the API refuses to start without one
echo "JWT_SIGNING_KEY=$(openssl rand -base64 48)" >> .env

docker compose up -d --build
node tools/seed-demo.mjs            # creates a demo vault with five items
```

Open <http://localhost:8080> and sign in:

| Email | Master password |
|---|---|
| `demo@securevault.app` | `demo-vault-password-2026` |

Now look at what the server actually stored:

```bash
docker compose exec db psql -U securevault -d securevault \
  -c 'SELECT "Type", left("EncryptedData", 44) AS ciphertext FROM "VaultItems";'
```

```
 Type |                   ciphertext
------+-----------------------------------------------
    0 | 3pNrgSmXeje5XBoUNFRY23bfXq0uFmiqhSCM65Ufqtpx...
    0 | DHbcP/2hLVBTun3famAfFyT73VLqtWPyZgtS7f1zZS2K...
    1 | eT3/H/9Wa3S3yXgkoOWX94H0fWaq3TOuNdqal1hLPkqE...
```

Then grep the entire database for a password you can see in the browser:

```bash
docker compose exec db pg_dump -U securevault securevault > dump.sql
grep -c 'H7v!qRm2xTp9Lc4Zs6Wd' dump.sql   # 0
grep -c 'Staging database'     dump.sql   # 0 — even item names are encrypted
grep -c 'demo@securevault.app' dump.sql   # 1 — the email is not secret, by design
```

The item names are not in there either. Only the email address, the KDF parameters, an
Argon2id verifier, and base64 ciphertext.

## How the zero-knowledge part works

Three derivations, all in the browser ([`frontend/src/crypto/`](frontend/src/crypto)):

```
masterKey   = PBKDF2-SHA256(masterPassword, kdfSalt, 600_000)      ── never sent
authHash    = PBKDF2-SHA256(masterKey, masterPassword, 1)          ── the only thing sent
wrappingKey = HKDF-SHA256(masterKey, "…vault-key-wrap:v1")         ── never sent
```

The server receives `authHash` and stores `Argon2id(authHash)` — so even the value it is
given is not what it keeps. A separate random 256-bit **vault key** encrypts every item;
that key is itself encrypted under `wrappingKey` and stored as an opaque blob.

That indirection is what makes a master password change cheap: it re-wraps 32 bytes
rather than re-encrypting the whole vault.

```
       browser                    │    server
  ─────────────────────────────── │ ────────────────────────
  master password                 │
        │ PBKDF2 600k             │
        ▼                         │
     masterKey ──── PBKDF2 ──► authHash ──► Argon2id(authHash)   stored
        │                         │
        │ HKDF                    │
        ▼                         │
   wrappingKey ──► AES-GCM ──► protectedVaultKey                 stored (opaque)
                       │        │
                   vaultKey ──► AES-GCM ──► item ciphertext      stored (opaque)
```

The browser can never be tricked into weakening this: the client rejects any KDF
iteration count below 100,000, even if the server asks for it, and `wrappingKey` is
imported as non-extractable so page code cannot read its bytes.

## What it does

- **Vault** — logins, notes and cards. Client-side search, since the server has nothing
  searchable to offer. Optimistic concurrency, so two tabs cannot silently clobber one
  another.
- **Two-factor authentication** — TOTP with a setup-then-prove flow, so you cannot lock
  yourself out with a secret your app never received. Eight single-use recovery codes,
  stored only as hashes.
- **Sessions** — see every device you are signed in on, with IP and user agent, and
  revoke any of them. Refresh tokens are single-use, and replaying a rotated one revokes
  the whole family.
- **Audit log** — every security-relevant event on your account.
- **Password generator** — rejection-sampled from `crypto.getRandomValues`, with a live
  entropy estimate. (`random % alphabet.length` biases toward the first characters; this
  does not do that.)
- **Breach check** — against Have I Been Pwned's k-anonymity API. The browser sends the
  first five characters of a SHA-1 hash and compares the returned list locally. The
  request goes straight to HIBP rather than through this API, because proxying it would
  hand our own server a stream of password prefixes.

## Running it

### With Docker (everything)

```bash
cp .env.example .env
echo "JWT_SIGNING_KEY=$(openssl rand -base64 48)" >> .env
docker compose up -d --build
```

<http://localhost:8080>. Both containers run as non-root; nginx serves the SPA, proxies
`/api` so the browser stays same-origin, and sets the CSP.

### Locally, for development

```bash
# Postgres only
docker compose up -d db

# API — http://localhost:5080, with API docs at /scalar
cd backend
dotnet run --project src/SecureVault.Api

# Web — http://localhost:5173, proxying /api to the API
cd frontend
npm install
npm run dev
```

The development signing key is committed in `appsettings.Development.json` on purpose, so
the project runs immediately after cloning. It is worthless — it signs tokens for a local
database of fake data — and production reads `Jwt__SigningKey` from the environment and
**refuses to start** if it is missing or shorter than 32 characters.

## Tests

```bash
cd backend  && dotnet test   # 48 tests
cd frontend && npm run test  # 26 tests
```

The backend suite boots the real pipeline — real authentication, real rate limiting, real
authorization — against SQLite. The tests worth reading are the adversarial ones:

| Test | What it pins down |
|---|---|
| `An_unknown_account_and_a_wrong_password_are_indistinguishable` | No account enumeration via login |
| `Prelogin_returns_a_stable_decoy_salt_for_the_same_unknown_email` | A salt that changed per request would itself be the tell |
| `One_user_cannot_read_another_users_item` | 404 rather than 403 — a 403 confirms the id exists |
| `Replaying_an_old_token_kills_the_whole_family` | Refresh-token theft is detected and contained |
| `A_recovery_code_works_once_and_then_never_again` | Single-use really means single-use |
| `Repeated_failures_lock_the_account_even_for_the_right_password` | Online guessing is stopped |
| `rejects_a_blob_that_has_been_tampered_with` | GCM authentication catches a modified database |
| `leaks_no_plaintext_into_the_blob` | The ciphertext really is opaque |

CI runs both suites, lints, builds both container images, then stands up the whole stack
and seeds a vault through the public API — so the end-to-end path is proven on every push,
not just the units. It also fails the build on any known-vulnerable dependency.

## Layout

```
backend/
  src/SecureVault.Api/
    Domain/        entities; comments explain what is deliberately visible to the server
    Data/          EF Core context and migrations
    Services/      Argon2id hashing, token rotation, TOTP, audit, secret protection
    Controllers/   auth, vault, account, sessions, audit
    Security/      JWT, rate-limit and lockout options
  tests/           48 unit and integration tests
frontend/
  src/crypto/      KDF, AES-GCM, generator, HIBP — the security-critical code
  src/api/         typed client with serialised refresh
  src/state/       auth and vault-key lifetime
  src/pages/       login, register, vault, settings
tools/seed-demo.mjs  seeds the demo vault — necessarily as a client, not from the server
docs/THREAT-MODEL.md
```

## Decisions worth defending

**PBKDF2 in the browser, Argon2id on the server.** PBKDF2 is native to WebCrypto, so it
runs as compiled code with no WASM download; a pure-JS Argon2 would do fewer iterations
per second and be *weaker* at the same wall-clock cost. Memory-hardness is applied where
it genuinely defends — the server-side verifier an attacker would crack offline.

**Tokens in memory, never in `localStorage`.** Web storage is readable by any script on
the origin, so a refresh token there is a persistent account takeover waiting for one XSS
bug. The cost is that a page reload signs you out — which for a password manager is the
correct default anyway, since the vault key cannot survive a reload either.

**No shared vaults.** Sharing needs key exchange between users, which is where
zero-knowledge designs most often break. An interviewer will probe exactly that. Shipping
it badly would be worse than not shipping it; the design sketch is in the threat model.

**No password reset, ever.** The server holds no key, so it cannot re-encrypt anything. An
email-based reset would mean the server *could* decrypt vaults — which would make every
claim in this README false.

## What this does not protect against

Spelled out properly in the [threat model](docs/THREAT-MODEL.md), but the headline:

**A compromised server can serve modified JavaScript that captures the master password as
you type it.** No browser-delivered zero-knowledge product escapes this, including the
commercial ones — the attacker controls the code doing the encrypting. A strict CSP raises
the cost; Subresource Integrity, reproducible builds, or a native client would be the real
answer. SecureVault ships the CSP and stops there.

Likewise, cross-site scripting on an unlocked page reads the decrypted vault, and so does
anyone at your unlocked laptop. Section 8 of the threat model lists every known gap and
what would close it.

## Licence

MIT.
