---
name: pebble-security
description: How to correctly issue and verify JWTs and application tokens, encrypt values, hash passwords and generate random identifiers using the sopheos/pebble_security PHP library (namespace Pebble\Security — classes JWT, Token, TokenException, Exception, Crypto and the deprecated Hash and Password). Use this whenever the project's composer.json requires sopheos/pebble_security, code imports from Pebble\Security\*, or you're asked to add/change authentication, a bearer token, an API key check, a login/password flow, a "remember me" or reset token, an OTP/verification code, a UUID, or encryption of a stored value in a PHP project that has this library available — even if the request is phrased generically like "protect this endpoint", "hash the password" or "generate a 6-digit code" without naming the library. Also check this before calling JWT::decode, Crypto or Hash in such a project, since this library has non-obvious behavior (verify binds the algorithm family to the key type, $expectedAlg pins the exact algorithm, Hash is a deprecated facade delegating to Crypto, Crypto::make() is deprecated and builds an instance while Hash::make() hashes, Crypto encode()/decode() are deprecated aliases of encrypt()/decrypt() and still read legacy CBC ciphertexts, Password is a deprecated facade of Crypto::passwordHash()/passwordVerify(), uuid() is a time-ordered v7) that naive code would walk straight into.
---

# pebble-security

`sopheos/pebble_security` is a small, dependency-free PHP 8.1+ security toolbox built on `ext-openssl`: a self-contained `JWT` implementation (HS*, RS*, ES*), a `Token` wrapper that adds a `uuid` and an optional device-bound proof, and a `Crypto` class (authenticated `aes-256-gcm` encryption plus static hashing, bcrypt password, random, UUID and OTP helpers). `Hash` and `Password` are deprecated facades that delegate to `Crypto`. Several parts are **not safe by default** and are listed as bugs in the package's `TODO.md`; this skill tells you which calls are fine and which to avoid.

Namespace: `Pebble\Security\*`. Source lives in `vendor/sopheos/pebble_security/src/`. Read it directly when you need an exact method signature; this skill focuses on *how to use the pieces safely* and the behavior that isn't obvious from the method names.

## Orientation

- `JWT` is all static. `encode()` signs, `decode()` verifies the signature and then `nbf`/`iat`/`exp`, and throws `Pebble\Security\Exception` on any failure.
- `Token` is the preferred entry point for app tokens. It always passes its own algorithm to `JWT::decode()`, so it is protected against algorithm confusion. All decode errors become `TokenException('token_invalid')`.
- `Crypto` encrypts with `aes-256-gcm` (random IV, authentication tag, sha256-derived key) and still reads legacy `aes-256-cbc` values. It also holds the static helpers `hash()`, `salt()`, `random()`, `uuid()`, `otp()`, `email()`, `passwordHash()` and `passwordVerify()`.
- `Password` is **deprecated**: `hash()`/`verify()` delegate to `Crypto::passwordHash()`/`Crypto::passwordVerify()`, `setSalt()` does nothing. Write `Crypto::passwordX()` in new code.
- `Hash` is **deprecated**: each method delegates to `Crypto` (`Hash::make()` → `Crypto::hash()`). Write `Crypto::x()` in new code.

For a full method cheat sheet, see `references/api-reference.md`. For the complete list of easy-to-miss behaviors, see `references/gotchas.md`.

## Core recipes

### Issue and check an app token (preferred)

```php
use Pebble\Security\JWT;
use Pebble\Security\Token;
use Pebble\Security\TokenException;

// Issue
$jwt = (new Token($issuer, $secret, JWT::HS256, $deviceId))
    ->add('user', $user->id)
    ->generate(3600);                      // adds iat and exp = now + 3600

// Check
try {
    $token = (new Token($issuer, $secret, JWT::HS256, $deviceId))
        ->import($_SERVER['HTTP_AUTHORIZATION'] ?? '');   // "Bearer " prefix accepted
    $userId = $token->get('user');
} catch (TokenException $e) {
    // $e->getMessage() is 'token_required' or 'token_invalid'
}
```

`$secret` must be at least 32 bytes for HS256 (48 for HS384, 64 for HS512), e.g. `Crypto::random(64)`: a shorter secret raises an `E_USER_DEPRECATED` and will be rejected in the next major version.

The importer must use the **same `$proof`** as the issuer. An importer built without a proof accepts any token and drops its `hash` claim.

### Raw JWT: pass `$expectedAlg`

```php
$payload = JWT::decode($jwt, $secret, true, JWT::HS256);           // HMAC
$payload = JWT::decode($jwt, $publicPem, true, JWT::RS256);        // RSA, public key
```

The key decides the algorithm family: an HS* token is never verified against a PEM (no algorithm confusion), and an RS*/ES* token sent to an HMAC endpoint is simply rejected, without PHP warning. Still pass the fourth argument: it pins the exact algorithm within a family (`HS256` vs `HS512`, `RS256` vs `RS512`). Never pass `$verify = false` on untrusted input.

HS*, RS* and ES* are all interoperable with other JWT libraries. ES* signatures are raw R||S (RFC 7518); legacy DER signatures from earlier versions are still accepted for now.

### Passwords

```php
use Pebble\Security\Crypto;

$hash = Crypto::passwordHash($plain);               // bcrypt, PHP default cost
$hash = Crypto::passwordHash($plain, 12);           // pinned cost
$ok   = Crypto::passwordVerify($plain, $hash);
```

In existing code, `(new Password())->setCost($c)->hash()` still works and delegates here.

### Random values

```php
use Pebble\Security\Crypto;

$apiKey = Crypto::random(64);      // random_bytes, 64 hex chars
$code   = Crypto::otp(6);          // random_int, zero-padded, 1 to 18 digits
$id     = Crypto::uuid();          // RFC 9562 v7, time-ordered
$digest = Crypto::hash($s, 64);    // sha256 hex
```

`uuid()` is a v7: its first 12 hex digits are the creation time in milliseconds. It is unique and sortable, but don't use it as a secret; use `Crypto::random()` for that.

### Encrypting a stored value

```php
use Pebble\Security\Crypto;

$stored = (new Crypto())->encrypt($plain, $key);      // base64(iv . tag . ciphertext)
$plain  = (new Crypto())->decrypt($stored, $key);     // null if wrong key or tampered
```

Each call gives a different output (random IV). `null` only means failure: `'0'` and `''` round-trip. Values encrypted by older versions (`aes-256-cbc`, key-derived IV) are still decrypted; re-encrypt them to migrate. `encode()`/`decode()` are deprecated aliases.

## Behavior to keep in mind while writing code

- **The key decides the algorithm family.** HS* is never verified against a PEM; RS*/ES* need a public key (or certificate) of the right type and curve. `$expectedAlg` additionally pins the exact algorithm: pass it. `Token::import()` does it for you.
- **`alg: none` is rejected** ("Algorithm not supported").
- **Claims are checked with a 30 s leeway** (`JWT::$leeway`), so a token stays valid up to 30 s after `exp`. `exp`/`nbf`/`iat` must be numbers ("Invalid claim …" otherwise); `exp: 0` is expired. `JWT::$timestamp` is a static override; reset it to `0` after tests.
- **`$verify = false` skips the signature but still checks `nbf`/`iat`/`exp`.**
- **`Token::import()` maps every failure to `token_invalid`**, including expiry and wrong algorithm.
- **`Crypto::make()` is deprecated (use `new Crypto()`) and builds an instance; `Hash::make()` returns a digest.** Use `Crypto::hash()` for digests.
- **`Crypto::decrypt()` falls back to legacy `aes-256-cbc`** for block-sized inputs; on that path only, a wrong key can return garbage instead of `null`.
- **The default bcrypt cost depends on the PHP version** (10 before 8.4, 12 since). Pass `$cost` to `Crypto::passwordHash()` to pin it.
- **`Crypto::hash()` and `Crypto::salt()` fall back to sha1 (40 chars) for any length other than 32, 40, 64 or 128.**
- **`Crypto::otp()` throws `ValueError` outside 1–18 digits; `Crypto::uuid()` is a time-ordered v7, not a random v4.**

Read `references/gotchas.md` for the rest before relying on an edge case.
