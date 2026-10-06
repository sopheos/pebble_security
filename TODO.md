# TODO — pebble_security

Open issues found during the 2026-10-06 audit. Each bug is pinned by a test that checks the current behavior: update it when fixing the bug.

## Debt / quality

- [ ] `JWT::verify()`: the fallback accepting legacy DER ES* signatures should be removed once tokens issued before the switch to R||S have expired.
- [ ] `Crypto::decrypt()`: the fallback reading legacy `aes-256-cbc` ciphertexts (`decryptLegacy()`) should be removed once the data has been rewritten. While it exists, a wrong key on a ciphertext whose size is a multiple of 16 bytes can return garbage instead of `null` (about 1 in 256).
- [ ] `JWT`: HMAC secrets shorter than the hash output (32/48/64 bytes for HS256/384/512) raise a one-time `E_USER_DEPRECATED`: reject them in a major version.
- [ ] `Hash`, `Password`, `Crypto::make()`, `Crypto::encode()` and `Crypto::decode()` are deprecated: remove them in a major version.
