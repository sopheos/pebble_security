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
| `HS256`, `HS384`, `HS512` | HMAC | shared secret | same secret |
| `RS256`, `RS384`, `RS512` | RSA | private PEM | public PEM |
| `ES256`, `ES384`, `ES512` | ECDSA (DER signature, non-standard) | private PEM | public PEM |

`decode()` order: non-empty key → parse → `alg` present and supported → `alg === $expectedAlg` (if given) → signature (if `$verify`) → `nbf` → `iat` → `exp`. Exception messages: `Key may not be empty`, `Wrong number of segments`, `Invalid segment encoding`, `Empty algorithm`, `Algorithm not supported`, `Unexpected algorithm`, `Signature verification failed`, `Cannot handle token prior to …`, `Expired token`.

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
| Strip `Bearer ` | `Token::parseToken(string $token): string` |

`TokenException::required()` → `'token_required'`, `TokenException::invalid()` → `'token_invalid'`.

## Crypto (`Pebble\Security\Crypto`)

| Intent | Method |
| ------ | ------ |
| Build | `new Crypto($method = null)` / `Crypto::make($method = null): static` (default `Crypto::METHOD = 'aes-256-cbc'`) |
| Encrypt to base64 (`''` on failure) | `encode(string $str, string $key): string` |
| Decrypt (`null` on failure or falsy plaintext) | `decode(string $str, string $key): ?string` |

## Password (`Pebble\Security\Password`)

| Intent | Method |
| ------ | ------ |
| bcrypt cost (ignored if falsy) | `setCost($cost): static` |
| Salt (**no effect, PHP warning**) | `setSalt($salt): static` |
| Hash | `hash($password): string` |
| Verify (`false` if either side is falsy) | `verify($password, $hash): bool` |

## Hash (`Pebble\Security\Hash`, static)

| Intent | Method | Notes |
| ------ | ------ | ----- |
| Hex digest by length | `make($string, $length = 40)` | 32 md5, 40 sha1, 64 sha256, 128 sha512, else sha1 |
| Random salt | `salt($length = 40)` | `make(random_bytes($length), $length)` |
| Random hex string | `random(int $length = 40): string` | `random_bytes`, safe |
| UUID-shaped string | `uuid()` | `uniqid()` + 19 random hex, **not v4** |
| Numeric code | `otp(int $len = 6): string` | `mt_rand`, **not safe** |
| Pseudonymised email | `email(string $email): ?string` | `sha1(name)@sha1(domain).tld`, `null` if invalid |
