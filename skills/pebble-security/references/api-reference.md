# pebble-security — API cheat sheet

Quick lookup by intent. This is not exhaustive. Read the source in `vendor/sopheos/pebble_security/src/` for exact signatures and for edge cases not covered here.

## JWT (`Pebble\Security\JWT`, static)

| Intent | Method |
| ------ | ------ |
| Sign a payload | `encode(array $payload, string $key, string $algo = JWT::HS256, ?string $keyId = null, ?array $head = null): string` |
| Verify and read a token | `decode(string $jwt, string $key, bool $verify = true, ?string $expectedAlg = null): array` |
| Split without verifying | `parse(string $jwt): array` → `[$headb64, $bodyb64, $cryptob64, $header, $payload, $signature]` |
| Strip a `Bearer ` prefix | `getBearerToken(string $token): string` |
| Raw signature | `sign($msg, $key, $alg = JWT::HS256): string` (binary) |
| Raw verification | `verify(string $msg, string $signature, string $key, string $alg = JWT::HS256): bool` |

Statics: `JWT::$leeway = 30` (seconds), `JWT::$timestamp = 0` (`0` means `time()`).

| Constant | Family | `$key` for encode | `$key` for decode |
| -------- | ------ | ----------------- | ----------------- |
| `HS256`, `HS384`, `HS512` | HMAC | shared secret (≥ 32/48/64 bytes, else `E_USER_DEPRECATED`) | same secret |
| `RS256`, `RS384`, `RS512` | RSA | private PEM | public PEM |
| `ES256`, `ES384`, `ES512` | ECDSA (raw R||S signature, RFC 7518; legacy DER still verified) | private PEM | public PEM |

Algorithm names are case-insensitive (`hs256` = `HS256`); `encode()` writes them upper case. Header parameter and claim names are lower case only (`exp`, not `EXP`).

`decode()` order: non-empty key → parse → `alg` present, a string and supported → `alg === $expectedAlg` (if given) → signature (if `$verify`; fails if the key does not match the algorithm family, type or curve) → `nbf` → `iat` → `exp`. Exception messages: `Key may not be empty`, `Wrong number of segments`, `Invalid segment encoding`, `Empty algorithm`, `Algorithm not supported`, `Unexpected algorithm`, `Signature verification failed`, `Invalid claim exp|nbf|iat` (not a number), `Cannot handle token prior to …`, `Expired token`.

## Token (`Pebble\Security\Token`)

| Intent | Method |
| ------ | ------ |
| Create | `new Token(string $url, string $key, string $alg, ?string $proof = null)` |
| Reset the payload (keeps its `uuid` if present) | `init(array $payload = []): static` |
| Set / remove a claim (`null` removes) | `add(string $name, $value): static` / `del(string $name): static` |
| Read a claim | `get(string $name, mixed $default = null): mixed` |
| Accessors | `url()`, `key()`, `alg()`, `uuid()`, `proof(): ?string`, `hash(): ?string` (sha1 of proof), `payload(): array` |
| Sign (adds `iat`, and `exp` if `$exp > 0`) | `generate(int $exp = 0): string` |
| Verify and load | `import(string $token): static` |
| Strip `Bearer ` (same as `JWT::getBearerToken()`) | `Token::parseToken(string $token): string` |

`TokenException::required()` → `'token_required'`, `TokenException::invalid()` → `'token_invalid'`.

## Crypto (`Pebble\Security\Crypto`)

| Intent | Method |
| ------ | ------ |
| Build | `new Crypto($method = null)` (`Crypto::make()` is deprecated; `$method` is ignored, kept for compatibility) |
| Encrypt with `aes-256-gcm` to `base64(iv . tag . ciphertext)` (`''` on failure) | `encrypt(string $str, string $key): string` |
| Decrypt, legacy CBC fallback (`null` on failure or tampering) | `decrypt(string $str, string $key): ?string` |
| Deprecated aliases of `encrypt()` / `decrypt()` | `encode()`, `decode()` |

| Intent | Static method | Notes |
| ------ | ------ | ----- |
| Hex digest by length | `hash(string $string, int $length = 40): string` | 32 md5, 40 sha1, 64 sha256, 128 sha512, else sha1 |
| Random salt | `salt(int $length = 40): string` | `hash(random_bytes($length), $length)` |
| Random hex string | `random(int $length = 40): string` | `random_bytes`, safe |
| UUID v7 | `uuid(): string` | ms timestamp + 74 random bits, RFC 9562 |
| Numeric code | `otp(int $len = 6): string` | `random_int`, 1–18 digits else `ValueError` |
| Pseudonymised email | `email(string $email): ?string` | `sha1(name)@sha1(domain).tld`, `null` if invalid; unkeyed, not dictionary-resistant |
| bcrypt hash | `passwordHash(string $password, ?int $cost = null): string` | PHP default cost if `$cost` is null |
| bcrypt verify | `passwordVerify(string $password, string $hash): bool` | `false` if either side is `''`; `'0'` is a valid password |

## Password (`Pebble\Security\Password`, deprecated)

Facade, every method delegates to `Crypto`:

| Intent | Method |
| ------ | ------ |
| bcrypt cost (ignored if falsy) | `setCost($cost): static` |
| Salt (**no effect**, deprecated no-op) | `setSalt($salt): static` |
| Hash → `Crypto::passwordHash()` | `hash($password): string` |
| Verify → `Crypto::passwordVerify()` | `verify($password, $hash): bool` |

## Hash (`Pebble\Security\Hash`, deprecated)

Static facade, every method delegates to `Crypto`: `make($string, $length = 40)` → `Crypto::hash()`; `salt()`, `random()`, `uuid()`, `otp()`, `email()` → the `Crypto` method of the same name.
