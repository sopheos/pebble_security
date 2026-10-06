<?php

use Pebble\Security\Crypto;
use PHPUnit\Framework\TestCase;

class CryptoTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Nominal
    // -------------------------------------------------------------------------

    public function testRoundTrip()
    {
        $crypto = Crypto::make();
        $encoded = $crypto->encode('hello world', 'secret');

        self::assertMatchesRegularExpression('#^[A-Za-z0-9/+=]+$#', $encoded);
        self::assertSame('hello world', $crypto->decode($encoded, 'secret'));
    }

    public function testDefaultMethodIsAes256Cbc()
    {
        $plain = new Crypto();
        $explicit = new Crypto('aes-256-cbc');

        self::assertSame($plain->encode('x', 'k'), $explicit->encode('x', 'k'));
    }

    public function testNonBase64InputDecodesToNull()
    {
        self::assertNull(Crypto::make()->decode('not base64!', 'secret'));
    }

    public function testWrongKeyUsuallyDecodesToNull()
    {
        $encoded = Crypto::make()->encode('secret message', 'right-key');

        self::assertNull(Crypto::make()->decode($encoded, 'wrong-key'));
    }

    // -------------------------------------------------------------------------
    // Known bugs (see TODO.md)
    // -------------------------------------------------------------------------

    public function testEncryptionIsDeterministic()
    {
        // BUG: the IV is derived from the key, so the same message always gives the same output.
        $crypto = Crypto::make();

        self::assertSame($crypto->encode('hello', 'secret'), $crypto->encode('hello', 'secret'));
    }

    public function testCiphertextIsMalleableWithoutMac()
    {
        // BUG: CBC with no MAC. Flipping a byte of block 1 rewrites the same byte of block 2.
        $crypto = Crypto::make();
        $raw = base64_decode($crypto->encode(str_repeat('A', 16) . 'amount=00000100;', 'k'));
        $raw[8] = chr(ord($raw[8]) ^ (ord('0') ^ ord('9')));

        $tampered = $crypto->decode(base64_encode($raw), 'k');

        self::assertSame('amount=09000100;', substr($tampered, 16));
    }

    public function testWrongKeyCanDecodeToGarbage()
    {
        // BUG: without a MAC, a wrong key that happens to yield valid padding returns garbage, not null.
        $encoded = Crypto::make()->encode('secret message', 'right-key');
        $decoded = Crypto::make()->decode($encoded, 'wrong-102');

        self::assertNotNull($decoded);
        self::assertNotSame('secret message', $decoded);
    }

    public function testKeyBytesBeyond32AreIgnored()
    {
        // BUG: openssl silently truncates the aes-256 key to 32 bytes.
        $base = str_repeat('a', 32);

        self::assertSame(Crypto::make()->encode('x', $base . 'A'), Crypto::make()->encode('x', $base . 'B'));
    }

    public function testFalsyPlaintextDecodesToNull()
    {
        // BUG: decode() ends with `?: null`, so '0' and '' cannot round-trip.
        $crypto = Crypto::make();

        self::assertNull($crypto->decode($crypto->encode('0', 'k'), 'k'));
        self::assertNull($crypto->decode($crypto->encode('', 'k'), 'k'));
    }

    public function testMultibyteKeyProducesAnOversizedIv()
    {
        // BUG: iv() uses mb_substr (characters, not bytes); a UTF-8 key yields a 32-byte IV
        // and openssl emits a warning.
        $warnings = [];
        set_error_handler(function ($no, $str) use (&$warnings) {
            $warnings[] = $str;
            return true;
        });

        try {
            Crypto::make()->encode('x', str_repeat('é', 16));
        } finally {
            restore_error_handler();
        }

        self::assertCount(1, $warnings);
        self::assertStringContainsString('IV passed is 32 bytes long', $warnings[0]);
    }
}
