# pebble-security — gotchas

Things the method names don't tell you, grouped by class. Every item below is pinned by a test in `tests/`. Items marked **(bug)** are listed in the package's `TODO.md` and may be fixed in a later version. Check the test of the same name in `vendor/sopheos/pebble_security/tests/` to see the current behavior.

## JWT

- **(bug) `decode()` trusts the header `alg` unless you pass `$expectedAlg`.** A token signed HS256 with an RSA *public* PEM as secret is accepted by `JWT::decode($jwt, $publicPem)`. Always pass the fourth argument; `Token::import()` does.
- **A mismatching `alg` is rejected when `$expectedAlg` is given** ("Unexpected algorithm").
- **`alg: none` is not supported** and is rejected before any signature check.
- **(bug) HMAC signatures are compared with `===`**, not `hash_equals()`.
- **(bug) ES256/384/512 signatures are DER-encoded** (about 70-72 bytes for ES256, first byte `0x30`), not the 64/96/132-byte R||S required by RFC 7518. A spec-compliant ES256 token from another library fails with "Signature verification failed", and other libraries reject this one's.
- **Claims are checked with a 30-second leeway.** With `exp = T`, the token is accepted until `T + 29` and rejected from `T + 30`. An `nbf` in the future (beyond the leeway) is rejected with "Cannot handle token prior to …".
- **`JWT::$timestamp` and `JWT::$leeway` are global statics.** Reset `$timestamp` to `0` after a test.
- **`$verify = false` skips only the signature**; `nbf`/`iat`/`exp` are still checked.
- **The `Bearer ` prefix is stripped** (case-insensitive) by `decode()` and `parse()`.
- **A token must have exactly three segments**, else "Wrong number of segments".
- **(bug) An empty payload cannot be decoded.** `JWT::encode([], …)` produces a token that `decode()` rejects with "Invalid segment encoding".
- **`encode()` merges `$head` over the default header**, after `kid`.

## Token

- **`import()` always enforces the constructor's algorithm**, so a token signed with another algorithm is `token_invalid`.
- **Every decode failure becomes `TokenException('token_invalid')`**: bad signature, expiry, malformed token. An empty string is `token_required`.
- **The proof is compared as `sha1($proof)` against the `hash` claim.** A different proof is `token_invalid`.
- **An importer built without a proof accepts any token and drops its `hash` claim**, because `init()` re-adds `hash` with `null`.
- **`add($name, null)` removes the claim**; `del()` is an alias.
- **`import()` keeps the token's `uuid`**, and `generate($exp)` sets `exp = iat + $exp`.

## Crypto

- **(bug) Encryption is deterministic.** The IV is the first 16 characters of the key, so the same message and key always give the same output.
- **(bug) No MAC: the ciphertext is malleable.** Flipping byte *i* of block N flips byte *i* of plaintext block N+1, and `decode()` returns the altered text without error.
- **(bug) A wrong key can decode to garbage** instead of `null` when the padding happens to be valid (about 1 key in 256).
- **(bug) Keys are truncated to 32 bytes** for `aes-256-cbc`: keys that differ only after byte 32 are equivalent.
- **(bug) `'0'` and `''` decode to `null`**, like a failure.
- **(bug) A multi-byte UTF-8 key makes an oversized IV** (16 characters, 32 bytes), and openssl emits a warning on every call.
- **`decode()` returns `null` for any input containing characters outside the base64 alphabet**, including whitespace and newlines.

## Password

- **(bug) `setSalt()` has no effect and makes `hash()` raise a PHP warning** ("The "salt" option has been ignored"). The hash is still valid.
- **(bug) `verify('0', $hash)` is always `false`**, because of an `!$password` guard.
- **`verify()` returns `false` when either argument is empty or null.**
- **The default bcrypt cost depends on PHP**: `$2y$10$` before 8.4, `$2y$12$` since. Use `setCost()` to pin it.

## Hash

- **`make()` and `salt()` fall back to sha1 (40 chars)** for any length other than 32, 40, 64 or 128. `salt(10)` returns 40 characters.
- **`random($n)` returns exactly `$n` lowercase hex characters** from `random_bytes()`.
- **(bug) `otp()` uses `mt_rand()`**: seeding with `mt_srand()` reproduces the same code.
- **(bug) `uuid()` starts with the Unix time.** Its first 8 hex digits are `dechex(time())` (from `uniqid()`).
- **(bug) `uuid()` has no version or variant bits.** The version character (index 14) is a `uniqid()` digit, not always `4`.
- **`email()` keeps the TLD in clear** (`sha1('john') . '@' . sha1('mail.co') . '.uk'`) and returns `null` for an invalid address.
