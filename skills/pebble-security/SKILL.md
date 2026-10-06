---
name: pebble-security
description: How to correctly issue and verify JWTs and application tokens, encrypt values, hash passwords and generate random identifiers using the sopheos/pebble_security PHP library (namespace Pebble\Security — classes JWT, Token, TokenException, Exception, Crypto, Password and Hash). Use this whenever the project's composer.json requires sopheos/pebble_security, code imports from Pebble\Security\*, or you're asked to add/change authentication, a bearer token, an API key check, a login/password flow, a "remember me" or reset token, an OTP/verification code, a UUID, or encryption of a stored value in a PHP project that has this library available — even if the request is phrased generically like "protect this endpoint", "hash the password" or "generate a 6-digit code" without naming the library. Also check this before calling JWT::decode, Crypto, Hash::otp or Hash::uuid in such a project, since this library has known security weaknesses (decode trusts the header alg unless you pass $expectedAlg, HMAC signatures are compared with ===, ES256/384/512 signatures are DER and not interoperable, Crypto uses a key-derived IV and no MAC, otp() uses mt_rand, uuid() is not a real v4, setSalt() is ignored with a warning) that naive code would walk straight into.
---

# pebble-security

`sopheos/pebble_security` is a small, dependency-free PHP 8.1+ security toolbox built on `ext-openssl`: a self-contained `JWT` implementation (HS*, RS*, ES*), a `Token` wrapper that adds a `uuid` and an optional device-bound proof, a symmetric `Crypto` helper, a bcrypt `Password` helper and assorted `Hash` functions. Several parts are **not safe by default** and are listed as bugs in the package's `TODO.md`; this skill tells you which calls are fine and which to avoid.

Namespace: `Pebble\Security\*`. Source lives in `vendor/sopheos/pebble_security/src/`. Read it directly when you need an exact method signature; this skill focuses on *how to use the pieces safely* and the behavior that isn't obvious from the method names.

## Orientation

- `JWT` is all static. `encode()` signs, `decode()` verifies the signature and then `nbf`/`iat`/`exp`, and throws `Pebble\Security\Exception` on any failure.
- `Token` is the preferred entry point for app tokens. It always passes its own algorithm to `JWT::decode()`, so it is protected against algorithm confusion. All decode errors become `TokenException('token_invalid')`.
- `Crypto` is **not** authenticated encryption. Use it only for low-value obfuscation, or not at all.
- `Password` is a thin `password_hash`/`password_verify` wrapper. Fine to use, but never call `setSalt()`.
- `Hash::make()`, `Hash::random()` and `Hash::salt()` are fine. `Hash::otp()` and `Hash::uuid()` are **not** cryptographically safe.

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

The importer must use the **same `$proof`** as the issuer. An importer built without a proof accepts any token and drops its `hash` claim.

### Raw JWT: always pass `$expectedAlg`

```php
$payload = JWT::decode($jwt, $secret, true, JWT::HS256);           // HMAC
$payload = JWT::decode($jwt, $publicPem, true, JWT::RS256);        // RSA, public key
```

**Never** call `JWT::decode($jwt, $key)` without the fourth argument. Without it the header's `alg` is trusted: a server that verifies RS256 with its public PEM will accept an HS256 token an attacker signed with that public PEM as HMAC secret. Never pass `$verify = false` on untrusted input.

Prefer HS* or RS*. **Do not use ES256/384/512** to talk to other systems: this library produces and expects DER signatures, while every other JWT library uses raw R||S, so tokens are rejected both ways.

### Passwords

```php
use Pebble\Security\Password;

$hash = (new Password())->hash($plain);             // bcrypt, PHP default cost
$ok   = (new Password())->verify($plain, $hash);
```

Don't call `setSalt()`: it does nothing and makes `hash()` raise a PHP warning (an exception under strict error handlers). `verify('0', …)` is always `false`.

### Random values

```php
use Pebble\Security\Hash;

$apiKey = Hash::random(64);                         // OK: random_bytes, hex
$code   = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);   // use instead of Hash::otp()
```

Don't use `Hash::otp()` for anything security-related (it uses `mt_rand`). Don't use `Hash::uuid()` where an unguessable or RFC-compliant v4 UUID is needed: its first 13 hex digits are `uniqid()` (the current time) and it has no version bits.

### Encrypting a stored value

Do **not** use `Crypto` for sensitive data. It is deterministic (key-derived IV), has no MAC (ciphertext can be tampered with undetected) and silently truncates keys to 32 bytes. Use libsodium instead:

```php
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$box = base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, $key32));
```

Only keep `Crypto` to read data that was already encrypted with it, with the **same key and method** (`Crypto::make()->decode($value, $key)`), and treat `null` as "failed or empty".

## Behavior to keep in mind while writing code

- **`JWT::decode()` trusts the header `alg` unless `$expectedAlg` is given.** Always pass it. `Token::import()` does it for you.
- **HMAC signatures are compared with `===`**, not `hash_equals()`: a theoretical timing leak.
- **ES* signatures are DER, not R||S.** Not interoperable with other JWT libraries.
- **`alg: none` is rejected** ("Algorithm not supported").
- **Claims are checked with a 30 s leeway** (`JWT::$leeway`), so a token stays valid up to 30 s after `exp`. `JWT::$timestamp` is a static override; reset it to `0` after tests.
- **`$verify = false` skips the signature but still checks `nbf`/`iat`/`exp`.**
- **A JWT with an empty payload cannot be decoded.**
- **`Token::import()` maps every failure to `token_invalid`**, including expiry and wrong algorithm.
- **`Crypto` is deterministic, malleable and may return garbage for a wrong key** instead of `null`. Keys longer than 32 bytes are truncated, multi-byte keys trigger an openssl warning, and `'0'` or `''` decode to `null`.
- **`Password::setSalt()` is ignored with a warning; `verify('0', …)` is always false.** The default bcrypt cost depends on the PHP version (10 before 8.4, 12 since).
- **`Hash::make()` and `Hash::salt()` fall back to sha1 (40 chars) for any length other than 32, 40, 64 or 128.**
- **`Hash::otp()` uses `mt_rand()`; `Hash::uuid()` is time-prefixed and not v4.**

Read `references/gotchas.md` for the rest before relying on an edge case.
