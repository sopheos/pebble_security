# CLAUDE.md — pebble_security

This file guides Claude Code when **maintaining** this library. To **use** it from a project, see the skill [`skills/pebble-security/`](skills/pebble-security/SKILL.md).

## Scope

`sopheos/pebble_security`, namespace `Pebble\Security\`, PHP >= 8.1, extensions `openssl` and `mbstring`, no runtime Composer dependency. The library provides:
- `JWT`: JWT encoding/decoding (HS*, RS*, ES*), without external dependency;
- `Token`: application layer over `JWT` (uuid, device-bound proof, `iat`/`exp`);
- `Crypto`: authenticated `aes-256-gcm` encryption and static helpers (hashing by length, random, UUID v7, OTP, email hashing, bcrypt);
- `Password`: deprecated, delegates to `Crypto::passwordHash()`/`passwordVerify()`;
- `Hash`: deprecated, each method delegates to `Crypto`.


## Commands

```bash
composer install
vendor/bin/phpunit            # whole suite
vendor/bin/phpunit --filter JWTTest
```

## Map of `src/`

| File | Role |
|---|---|
| `JWT.php` | `encode()`, `decode()` (signature then `nbf`/`iat`/`exp` with `$leeway`, read by `numericDate()`: must be numbers, `0` counts), `parse()`, `sign()`, `verify()`, `getBearerToken()`. `verify()` binds the algorithm family to the key (`isPem()`, `isKeyOf()`): HS* refuses a PEM, RS*/ES* require a public key of the right type and curve. Algorithm names are normalised to upper case by `alg()` (lower case accepted). Header parameter and claim names are read in lower case only (`$header['alg']`, `$payload['exp']`). Statics `$leeway` and `$timestamp`. `hmac()` raises a one-time `E_USER_DEPRECATED` (`$shortKeyWarned`) for a secret shorter than the hash output. ES*: `sign()` converts openssl's DER to R||S (`derToRaw()`), `verify()` converts back (`rawToDer()`) and falls back to DER for legacy tokens |
| `Token.php` | Mutable payload (`add`/`del`/`get`), `generate($exp)` (keeps an existing `exp` when `$exp` is 0, on purpose) and `import($jwt)`, which always passes the expected algorithm to `JWT::decode()` |
| `TokenException.php` | `token_required` and `token_invalid` |
| `Exception.php` | Exception thrown by `JWT` |
| `Crypto.php` | `encrypt()`/`decrypt()` with `aes-256-gcm` (`base64(iv . tag . ciphertext)`, sha256 key), `decryptLegacy()` fallback for legacy CBC ciphertexts. `encode()`/`decode()` deprecated (aliases). Statics `hash()`, `salt()`, `random()`, `uuid()`, `otp()`, `email()`, `passwordHash()`, `passwordVerify()` |
| `Password.php` | Deprecated. Facade: `hash()`/`verify()` delegate to `Crypto::passwordHash()`/`passwordVerify()` with the cost from `setCost()`. `setSalt()` has no effect |
| `Hash.php` | Deprecated. Static facade: each method delegates to `Crypto` (`make()` → `Crypto::hash()`, because `Crypto::make()`, also deprecated, builds an instance) |

## Tests

- PHPUnit 9.5. One file per class in `tests/`.
- Test classes have no namespace. Methods are named `testSentenceInCamelCase`, assertions use `self::assertSame`, and `// ----` banners separate sections.
- RSA and EC keys are generated in `JWTTest::setUpBeforeClass()` with `openssl_pkey_new()`: no key is committed.
- `JWT::$timestamp` and `JWT::$leeway` are static: `JWTTest::tearDown()` resets them to `0` and `30`.
- PHP warnings are captured with `set_error_handler()`, not `expectWarning()`.
- Tests use short HMAC secrets (`'secret'`): `tests/bootstrap.php` sets `JWT::$shortKeyWarned` to `true` by reflection, and the "Short HMAC secrets" tests re-arm it.

## Code conventions

Follow the existing style, without "modernising" it along the way:
- no `declare(strict_types=1)`;
- class constants without visibility;
- one-line `if` without braces allowed;
- `@return static` docblocks, comments in English.

Any behavior change must be reflected in `skills/pebble-security/` (SKILL.md, `references/api-reference.md`, `references/gotchas.md`) and in `README.md`. All documentation is in English.

A change to `JWT` that **changes the token format** (e.g. making `$expectedAlg` mandatory, which is not needed since `verify()` binds the key to the algorithm family) makes existing tokens unreadable. Plan a major version or a compatibility mode, like the DER fallback of `JWT::verify()` for legacy ES* signatures or `Crypto::decryptLegacy()` for legacy ciphertexts.

Do not touch the CBC fixtures in `tests/CryptoTest.php`: they were produced by the old `encode()` and guarantee that existing data stays readable.

## Known bugs

They are listed in [`TODO.md`](TODO.md). Each one is **pinned by a test** annotated `// BUG:` that checks the *current* behavior, in the "Known bugs" section of the test file of the class concerned.

To fix a bug:
1. Fix `src/`.
2. Rewrite the `// BUG:` test so it checks the expected behavior.
3. Update the "(bug)" entry in `skills/pebble-security/references/gotchas.md` and SKILL.md.
4. Remove the entry from `TODO.md` (it only lists what remains to be done).
