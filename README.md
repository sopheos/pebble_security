# Pebble/Security

Security tools from sopheos for PHP 8.1+: JWT (HS*, RS*, ES*), application tokens, symmetric encryption, bcrypt passwords and hashing helpers.

The library has no Composer dependency. It relies on the `openssl` and `mbstring` extensions. Known bugs and debt are listed in [`TODO.md`](TODO.md).

## Installation

```bash
composer require sopheos/pebble_security
```

## Claude Code

This package ships a Claude Code skill in [`skills/pebble-security/`](skills/pebble-security/). It documents the library's usage patterns and pitfalls: key/algorithm binding in `JWT`, passing the expected algorithm to `JWT::decode()`, ES* signature format, `Hash` and `Password` deprecated in favor of `Crypto`, reading legacy ciphertexts, etc.

In a project that depends on `sopheos/pebble_security`, copy it once into `.claude/skills/` after `composer install` so Claude Code loads it automatically. The folder name must match the `name` declared in `SKILL.md`:

```bash
cp -r vendor/sopheos/pebble_security/skills/pebble-security .claude/skills/pebble-security
```

To maintain the library itself, see [`CLAUDE.md`](CLAUDE.md). Known bugs are listed in [`TODO.md`](TODO.md).

## JWT

`\Pebble\Security\JWT` only has static methods. Errors throw `\Pebble\Security\Exception`.

* `encode(array $payload, string $key, string $algo = JWT::HS256, ?string $keyId = null, ?array $head = null) : string` Signs the payload. `$keyId` adds `kid` to the header, `$head` merges fields into it. For RS*/ES*, `$key` is the private PEM key.
* `decode(string $jwt, string $key, bool $verify = true, ?string $expectedAlg = null) : array` Verifies the signature, then `nbf`, `iat` and `exp`, and returns the payload. These claims must be numbers (numeric strings accepted, `null` = not set), else "Invalid claim …"; `0` is a real date, so `exp: 0` is expired. The `Bearer ` prefix is accepted. For RS*/ES*, `$key` is the public PEM key (or certificate). The key decides the algorithm family (see `verify()`), so a token signed with another family is rejected even without `$expectedAlg`. Passing `$expectedAlg` is still recommended: it also pins the exact algorithm (`HS256` vs `HS512`).
* `parse(string $jwt) : array` Splits without verifying: `[$headb64, $bodyb64, $cryptob64, $header, $payload, $signature]`.
* `getBearerToken(string $token) : string` Strips the `Bearer ` prefix.
* `sign($msg, $key, $alg = JWT::HS256) : string` Raw binary signature.
* `verify(string $msg, string $signature, string $key, string $alg = JWT::HS256) : bool` Verifies a signature. `verify()` binds the algorithm family to the key: an HS* signature is never checked against a PEM, and an RS*/ES* signature only against a public key (or certificate) of the right type and curve (RSA for RS*; P-256, P-384, P-521 for ES256/384/512). A mismatch is a plain verification failure, without PHP warning.
* `JWT::$leeway` Clock tolerance in seconds (30 by default).

HMAC secrets should be at least as long as the hash output (RFC 7518 §3.2): 32 bytes for HS256, 48 for HS384, 64 for HS512. A shorter secret still works but raises an `E_USER_DEPRECATED` (once per process) and will be rejected in the next major version. Generate one with `Crypto::random(64)` (64 hex characters, 32 bytes of entropy).

* `JWT::$timestamp` Forced timestamp for tests (`0` = `time()`).

Algorithms: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`. Names are case-insensitive everywhere (`encode()`, `decode()` header and `$expectedAlg`, `sign()`, `verify()`): `hs256` is `HS256`, and `encode()` always writes the upper-case name in the header. Header parameter and claim **names** are case-sensitive and read in lower case only: `ALG` or `EXP` are ordinary fields, not `alg` or `exp`. ES* signatures use the raw R||S format of RFC 7518, like other JWT libraries. During a transition period, `verify()` also accepts the DER signatures produced by earlier versions.

```php
use Pebble\Security\JWT;

$jwt = JWT::encode(['sub' => 42, 'exp' => time() + 3600], $secret, JWT::HS256);
$payload = JWT::decode($jwt, $secret, true, JWT::HS256);
```

## Token

`\Pebble\Security\Token` wraps a JWT payload with a `uuid` and, optionally, a proof (`proof`) whose sha1 is stored in the `hash` claim. Errors throw `\Pebble\Security\TokenException` (`token_required` or `token_invalid`).

* `__construct(string $url, string $key, string $alg, ?string $proof = null)` Initialises a payload with a new `uuid`.
* `init(array $payload = []) : static` Replaces the payload (keeping its `uuid` if it has one) and re-injects `uuid` and `hash`.
* `add(string $name, $value) : static` Adds a claim. `null` removes it.
* `del(string $name) : static` Removes a claim.
* `get(string $name, mixed $default = null) : mixed` Reads a claim.
* `url()`, `key()`, `alg()`, `uuid()`, `proof()`, `hash()`, `payload()` Accessors.
* `generate(int $exp = 0) : string` Adds `iat` (and `exp` = now + `$exp` if non-zero), then encodes. Without `$exp`, an existing `exp` is kept on purpose (re-signing does not extend the expiry).
* `import(string $token) : static` Decodes with the constructor's algorithm, checks the proof if set, then calls `init()` with the received payload.
* `parseToken(string $token) : string` Strips the `Bearer ` prefix (same as `JWT::getBearerToken()`).

```php
use Pebble\Security\JWT;
use Pebble\Security\Token;

$jwt = (new Token('https://api.example', $secret, JWT::HS256, $deviceId))
    ->add('user', 42)
    ->generate(3600);

$token = (new Token('https://api.example', $secret, JWT::HS256, $deviceId))->import($header);
$userId = $token->get('user');
```

## Crypto

`\Pebble\Security\Crypto` encrypts with `aes-256-gcm` (authenticated encryption) and returns `base64(iv . tag . ciphertext)`. The key is derived with sha256.

* `__construct($method = null)` / `make($method = null)` (**deprecated**, use `new Crypto()`) `$method` is obsolete and ignored, kept for compatibility. The `Crypto::METHOD` constant no longer exists.
* `encrypt(string $str, string $key) : string` Encrypts with a random IV. Returns `''` on failure.
* `decrypt(string $str, string $key) : ?string` Decrypts. Returns `null` if the key is wrong or the ciphertext was tampered with. Ciphertexts produced before the switch to GCM (`aes-256-cbc`, key-derived IV) are still readable: re-encrypt them with `encrypt()` to migrate.
* `encode()` / `decode()` (**deprecated**) Aliases of `encrypt()` and `decrypt()`.

Static methods (formerly on `Hash` and `Password`):

* `hash(string $string, int $length = 40) : string` Hex digest chosen by length: 32 md5, 40 sha1, 64 sha256, 128 sha512. Any other length gives sha1.
* `salt(int $length = 40) : string` Digest of `random_bytes()`. Same length rule.
* `random(int $length = 40) : string` Random hex string (`random_bytes`).
* `uuid() : string` UUID v7 (RFC 9562): millisecond timestamp followed by 74 random bits, sortable.
* `otp(int $len = 6) : string` Numeric code (`random_int`), zero-padded. Throws `ValueError` outside 1 to 18 digits.
* `email(string $email) : ?string` `sha1(name)@sha1(domain).tld`, or `null` if the email is invalid. Unkeyed sha1: not designed to resist a dictionary attack.
* `passwordHash(string $password, ?int $cost = null) : string` `password_hash()` with `PASSWORD_BCRYPT`. Without `$cost`, PHP's default cost.
* `passwordVerify(string $password, string $hash) : bool` `password_verify()`. Returns `false` if either is empty (`''`).

## Password

`\Pebble\Security\Password` is **deprecated**. Its methods keep their signature and delegate to `Crypto`:

* `setCost($cost)` bcrypt cost, passed to `Crypto::passwordHash()`. Ignored if falsy.
* `setSalt($salt)` **No effect** (the `salt` option is ignored since PHP 8.0). No longer raises a warning.
* `hash($password) : string` → `Crypto::passwordHash()`.
* `verify($password, $hash) : bool` → `Crypto::passwordVerify()`.

## Hash

`\Pebble\Security\Hash` is **deprecated**. Its methods keep their signature and delegate to `Crypto`: `make()` → `Crypto::hash()` (`Crypto::make()`, deprecated in favor of `new Crypto()`, builds an instance), `salt()`, `random()`, `uuid()`, `otp()` and `email()` → the method of the same name.

## Tests

```bash
composer install
vendor/bin/phpunit
```

RSA and EC keys are generated on the fly. Known bugs are pinned by tests annotated `// BUG:` that check the current behavior. Legacy `aes-256-cbc` ciphertexts are tested against values produced by the previous version.
