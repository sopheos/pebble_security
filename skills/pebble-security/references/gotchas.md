# pebble-security — gotchas

Things the method names don't tell you, grouped by class. Every item below is pinned by a test in `tests/`. Items marked **(bug)** are listed in the package's `TODO.md` and may be fixed in a later version. Check the test of the same name in `vendor/sopheos/pebble_security/tests/` to see the current behavior.

## JWT

- **The key decides the algorithm family, not the header.** A token signed HS256 with an RSA *public* PEM as secret is rejected by `JWT::decode($jwt, $publicPem)`, even without `$expectedAlg`: HS* never verifies against a key containing `-----BEGIN`. An RS*/ES* token decoded with an HMAC secret, an RSA key used for ES*, or a P-256 key used for ES512 fail as `Signature verification failed`, without PHP warning. An X.509 certificate is accepted as public key.
- **A mismatching `alg` is rejected when `$expectedAlg` is given** ("Unexpected algorithm").
- **Algorithm names are case-insensitive.** `hs256` works in `encode()`, `sign()`, `verify()`, `$expectedAlg` and in a received header; `encode()` writes `HS256` in the header. `$expectedAlg` still has to name the same algorithm (`hs512` header vs `hs256` expected: "Unexpected algorithm").
- **`exp`, `nbf` and `iat` must be numbers.** Any other value (`"tomorrow"`, `""`, `true`, an array) is rejected with "Invalid claim exp" (or `nbf`, `iat`). Numeric strings are accepted and compared as numbers, `null` means "not set". `0` is a real date: `exp: 0` is expired.
- **Header parameter and claim names are lower case only.** `{"ALG": ...}` is "Empty algorithm"; `EXP`, `NBF`, `IAT` are plain claims, not time checks. Always write `exp`, `nbf`, `iat`.
- **`alg: none` is not supported** and is rejected before any signature check.
- **HMAC signatures are compared with `hash_equals()`** (constant time).
- **A short HMAC secret is deprecated.** Below 32/48/64 bytes for HS256/384/512, `sign()`/`verify()` (so `encode()`, `decode()`, `Token`) raise one `E_USER_DEPRECATED` per process; the token still works. The next major version will reject it. Use `Crypto::random(64)` or longer.
- **ES256/384/512 signatures are raw R||S** (64, 96 or 132 bytes) as required by RFC 7518, so tokens are interoperable with other JWT libraries. `JWT::sign()` returns that format too, not openssl's DER.
- **Legacy DER ES* signatures are still accepted** by `verify()`/`decode()` (transition period): tokens issued by earlier versions keep working until they expire. This fallback will be removed.
- **Claims are checked with a 30-second leeway.** With `exp = T`, the token is accepted until `T + 29` and rejected from `T + 30`. An `nbf` in the future (beyond the leeway) is rejected with "Cannot handle token prior to …".
- **`JWT::$timestamp` and `JWT::$leeway` are global statics.** Reset `$timestamp` to `0` after a test.
- **`$verify = false` skips only the signature**; `nbf`/`iat`/`exp` are still checked.
- **The `Bearer ` prefix is stripped** (case-insensitive) by `decode()` and `parse()`.
- **A token must have exactly three segments**, else "Wrong number of segments".
- **An empty payload round-trips**: `decode(JWT::encode([], …))` returns `[]`. A payload that is not a JSON object or array is "Invalid segment encoding".
- **`encode()` merges `$head` over the default header**, after `kid`.

## Token

- **`import()` always enforces the constructor's algorithm**, so a token signed with another algorithm is `token_invalid`.
- **Every decode failure becomes `TokenException('token_invalid')`**: bad signature, expiry, malformed token. An empty string is `token_required`.
- **The proof is compared as `sha1($proof)` against the `hash` claim** with `hash_equals()`. A different proof, or a non-string `hash` claim, is `token_invalid`.
- **An importer built without a proof accepts any token and drops its `hash` claim**, because `init()` re-adds `hash` with `null`.
- **`add($name, null)` removes the claim**; `del()` is an alias.
- **`Token::parseToken()` is `JWT::getBearerToken()`.**
- **`import()` keeps the token's `uuid`**, and `generate($exp)` sets `exp = iat + $exp`.
- **`generate()` without `$exp` keeps the existing `exp`** (on purpose): re-signing an imported token refreshes `iat` without extending its expiry. Call `del('exp')` first to drop it.

## Crypto

- **`encrypt()` always uses `aes-256-gcm`** (authenticated encryption) with a random 12-byte IV. Output is `base64(iv . tag . ciphertext)`, so the same message encrypts differently every time.
- **The key is hashed with sha256** before use: keys of any length (including multi-byte UTF-8) are fully used and give 32-byte keys.
- **Tampering or a wrong key makes `decrypt()` return `null`**, never garbage, for anything produced by `encrypt()`.
- **`encode()` / `decode()` are deprecated aliases** of `encrypt()` / `decrypt()`.
- **`'0'` and `''` round-trip.** `null` only means failure.
- **The constructor's `$method` is ignored**, kept for compatibility. `Crypto::METHOD` no longer exists.
- **Legacy `aes-256-cbc` ciphertexts (key-derived IV, no MAC) are still readable** by `decrypt()` as a fallback when the GCM check fails and the input is a multiple of 16 bytes. On that path a wrong key can still decode to garbage (about 1 in 256). Re-encrypt legacy values to migrate them.
- **The format is plain and portable**: any `aes-256-gcm` implementation with a 12-byte IV, a 16-byte tag and `sha256($key)` as key can read or produce it.
- **`decrypt()` returns `null` for any input containing characters outside the base64 alphabet**, including whitespace and newlines.
- **Static helpers live on `Crypto` too**: `hash()`, `salt()`, `random()`, `uuid()`, `otp()`, `email()` (formerly on `Hash`), `passwordHash()`, `passwordVerify()` (formerly on `Password`).

## Passwords (`Crypto::passwordHash()` and the deprecated `Password`)

- **`Password` is deprecated.** `hash()` → `Crypto::passwordHash($password, $cost)`, `verify()` → `Crypto::passwordVerify()`. `null` arguments are cast to `''`.
- **`Password::setSalt()` is a deprecated no-op**: the salt never reaches `password_hash()`, so no warning is raised.
- **`passwordVerify()` returns `false` when either argument is `''`.** `'0'` is checked like any other password.
- **The default bcrypt cost depends on PHP**: `$2y$10$` before 8.4, `$2y$12$` since. Pass `$cost` to `passwordHash()` to pin it.

## Crypto static helpers (and the deprecated `Hash`)

- **`Hash` is deprecated.** It does not extend `Crypto`; each static method delegates to it: `Hash::make()` → `Crypto::hash()`, every other `Hash::x()` → `Crypto::x()`.
- **`Crypto::make()` (deprecated, use `new Crypto()`) builds an instance, `Hash::make()` returns a digest.** Use `Crypto::hash()` for a digest.
- **`hash()` and `salt()` fall back to sha1 (40 chars)** for any length other than 32, 40, 64 or 128. `salt(10)` returns 40 characters.
- **`random($n)` returns exactly `$n` lowercase hex characters** from `random_bytes()`.
- **`otp()` uses `random_int()`**, can return `000000`, and throws `ValueError` outside 1–18 digits.
- **`uuid()` is an RFC 9562 v7**: the first 12 hex digits are the Unix time in milliseconds (sortable, not secret), followed by 74 random bits.
- **`email()` keeps the TLD in clear** (`sha1('john') . '@' . sha1('mail.co') . '.uk'`) and returns `null` for an invalid address.
- **`email()` is unkeyed sha1, not designed to resist a dictionary attack**: a common address can be recovered from its hash. Don't use it where the address must stay secret.
