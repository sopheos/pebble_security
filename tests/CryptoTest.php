<?php

use Pebble\Security\Crypto;
use PHPUnit\Framework\TestCase;

class CryptoTest extends TestCase
{
    // -------------------------------------------------------------------------
    // encrypt / decrypt
    // -------------------------------------------------------------------------

    public function testRoundTrip()
    {
        $crypto = new Crypto();
        $encrypted = $crypto->encrypt('hello world', 'secret');

        self::assertMatchesRegularExpression('#^[A-Za-z0-9/+=]+$#', $encrypted);
        self::assertSame('hello world', $crypto->decrypt($encrypted, 'secret'));
    }

    public function testOutputIsBase64OfIvTagAndCiphertext()
    {
        $raw = base64_decode((new Crypto())->encrypt('hello', 'k'));

        self::assertSame(12 + 16 + 5, strlen($raw));
    }

    public function testEncryptionIsRandomised()
    {
        $crypto = new Crypto();

        self::assertNotSame($crypto->encrypt('hello', 'secret'), $crypto->encrypt('hello', 'secret'));
    }

    public function testDeprecatedEncodeAndDecodeDelegateToEncryptAndDecrypt()
    {
        $crypto = new Crypto();

        self::assertSame('x', $crypto->decrypt($crypto->encode('x', 'k'), 'k'));
        self::assertSame('x', $crypto->decode($crypto->encrypt('x', 'k'), 'k'));
        self::assertNull($crypto->decode('not base64!', 'k'));
    }

    public function testDeprecatedMakeBuildsAnInstance()
    {
        self::assertInstanceOf(Crypto::class, Crypto::make());
        self::assertSame('x', Crypto::make()->decrypt((new Crypto())->encrypt('x', 'k'), 'k'));
    }

    public function testMethodArgumentIsIgnored()
    {
        $encrypted = (new Crypto('aes-128-cbc'))->encrypt('x', 'k');

        self::assertSame('x', (new Crypto('aes-128-cbc'))->decrypt($encrypted, 'k'));
        self::assertSame('x', (new Crypto())->decrypt($encrypted, 'k'));
    }

    public function testNonBase64InputDecodesToNull()
    {
        self::assertNull((new Crypto())->decrypt('not base64!', 'secret'));
        self::assertNull((new Crypto())->decrypt('', 'secret'));
    }

    public function testWrongKeyDecodesToNull()
    {
        $encrypted = (new Crypto())->encrypt('secret message', 'right-key');

        self::assertNull((new Crypto())->decrypt($encrypted, 'wrong-key'));
    }

    public function testTamperedCiphertextDecodesToNull()
    {
        $crypto = new Crypto();
        $raw = base64_decode($crypto->encrypt('amount=00000100;', 'k'));
        $raw[30] = chr(ord($raw[30]) ^ 1);

        self::assertNull($crypto->decrypt(base64_encode($raw), 'k'));
    }

    public function testWholeKeyIsUsed()
    {
        $base = str_repeat('a', 32);
        $encrypted = (new Crypto())->encrypt('x', $base . 'A');

        self::assertSame('x', (new Crypto())->decrypt($encrypted, $base . 'A'));
        self::assertNull((new Crypto())->decrypt($encrypted, $base . 'B'));
    }

    public function testFalsyPlaintextRoundTrips()
    {
        $crypto = new Crypto();

        self::assertSame('0', $crypto->decrypt($crypto->encrypt('0', 'k'), 'k'));
        self::assertSame('', $crypto->decrypt($crypto->encrypt('', 'k'), 'k'));
    }

    public function testMultibyteKeyRaisesNoWarning()
    {
        $key = str_repeat('é', 16);
        $warnings = [];
        set_error_handler(function ($no, $str) use (&$warnings) {
            $warnings[] = $str;
            return true;
        });

        try {
            $decoded = (new Crypto())->decrypt((new Crypto())->encrypt('x', $key), $key);
        } finally {
            restore_error_handler();
        }

        self::assertSame('x', $decoded);
        self::assertSame([], $warnings);
    }

    public function testDecodesAPlainAes256GcmPayload()
    {
        // Format: base64(iv . tag . ciphertext), key = sha256(key)
        $iv = random_bytes(12);
        $ssl = openssl_encrypt('shared', 'aes-256-gcm', hash('sha256', 'k', true), OPENSSL_RAW_DATA, $iv, $tag);

        self::assertSame('shared', (new Crypto())->decrypt(base64_encode($iv . $tag . $ssl), 'k'));
    }

    // -------------------------------------------------------------------------
    // passwordHash / passwordVerify
    // -------------------------------------------------------------------------

    public function testPasswordHashAndVerify()
    {
        $hash = Crypto::passwordHash('p4ssw0rd');

        // Default bcrypt cost depends on PHP (10 before 8.4, 12 since)
        self::assertMatchesRegularExpression('/^\$2y\$1[02]\$/', $hash);
        self::assertTrue(Crypto::passwordVerify('p4ssw0rd', $hash));
        self::assertFalse(Crypto::passwordVerify('wrong', $hash));
    }

    public function testPasswordHashAppliesCost()
    {
        self::assertStringStartsWith('$2y$04$', Crypto::passwordHash('x', 4));
    }

    public function testEmptyPasswordOrHashNeverVerifies()
    {
        self::assertFalse(Crypto::passwordVerify('', Crypto::passwordHash('', 4)));
        self::assertFalse(Crypto::passwordVerify('x', ''));
    }

    public function testPasswordZeroVerifies()
    {
        $hash = Crypto::passwordHash('0', 4);

        self::assertTrue(Crypto::passwordVerify('0', $hash));
        self::assertFalse(Crypto::passwordVerify('0', Crypto::passwordHash('1', 4)));
    }

    // -------------------------------------------------------------------------
    // Legacy aes-256-cbc ciphertexts (produced by the old encode())
    // -------------------------------------------------------------------------

    public function testLegacyCiphertextIsStillReadable()
    {
        self::assertSame('legacy message', (new Crypto())->decrypt('y/1fM7IPzs1JYEj9myNrrQ==', 'legacy-key'));
        self::assertSame('hello', (new Crypto())->decrypt('AnnVhj3XABd/0NFCmzhrdw==', 'k'));
    }

    public function testLegacyCiphertextWithWrongKeyIsNotTheMessage()
    {
        self::assertNotSame('legacy message', (new Crypto())->decrypt('y/1fM7IPzs1JYEj9myNrrQ==', 'other-key'));
    }

    public function testLegacyFallbackOnlyAppliesToBlockSizedInput()
    {
        // 12 (iv) + 16 (tag) + 14 = 42 bytes: not a multiple of 16, no CBC fallback
        $encrypted = (new Crypto())->encrypt('secret message', 'right-key');

        self::assertNotSame(0, strlen(base64_decode($encrypted)) % 16);
        self::assertNull((new Crypto())->decrypt($encrypted, 'wrong-key'));
    }
}
