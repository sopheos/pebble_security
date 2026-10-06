<?php

use Pebble\Security\Exception;
use Pebble\Security\JWT;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    private static array $rsa = [];
    private static array $ec = [];

    public static function setUpBeforeClass(): void
    {
        self::$rsa = self::keyPair(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::$ec = self::keyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    }

    protected function tearDown(): void
    {
        JWT::$timestamp = 0;
        JWT::$leeway = 30;
    }

    private static function keyPair(array $options): array
    {
        $key = openssl_pkey_new($options);
        openssl_pkey_export($key, $private);

        return [$private, openssl_pkey_get_details($key)['key']];
    }

    private static function b64(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Converts a DER ECDSA signature (what openssl_sign returns) to raw R||S (RFC 7518).
     */
    private static function derToRaw(string $der, int $size): string
    {
        $offset = 3;
        $rLen = ord($der[$offset]);
        $r = substr($der, $offset + 1, $rLen);
        $offset += 1 + $rLen + 1;
        $sLen = ord($der[$offset]);
        $s = substr($der, $offset + 1, $sLen);

        $pad = fn($v) => str_pad(ltrim($v, "\0"), $size, "\0", STR_PAD_LEFT);

        return $pad($r) . $pad($s);
    }

    // -------------------------------------------------------------------------
    // Encode / decode
    // -------------------------------------------------------------------------

    public function testHs256RoundTrip()
    {
        $jwt = JWT::encode(['sub' => 42], 'secret');

        self::assertCount(3, explode('.', $jwt));
        self::assertSame(['sub' => 42], JWT::decode($jwt, 'secret', true, JWT::HS256));
    }

    public function testHeaderContainsKidAndExtraFields()
    {
        $jwt = JWT::encode(['a' => 1], 'secret', JWT::HS512, 'key-1', ['cty' => 'x']);
        [, , , $header] = JWT::parse($jwt);

        self::assertSame(['typ' => 'JWT', 'alg' => 'HS512', 'kid' => 'key-1', 'cty' => 'x'], $header);
    }

    public function testRs256SignsWithPrivateKeyAndVerifiesWithPublicKey()
    {
        [$private, $public] = self::$rsa;
        $jwt = JWT::encode(['a' => 1], $private, JWT::RS256);

        self::assertSame(['a' => 1], JWT::decode($jwt, $public, true, JWT::RS256));
    }

    public function testEs256RoundTripWithinThisLibrary()
    {
        [$private, $public] = self::$ec;
        $jwt = JWT::encode(['a' => 1], $private, JWT::ES256);

        self::assertSame(['a' => 1], JWT::decode($jwt, $public, true, JWT::ES256));
    }

    public function testBearerPrefixIsStripped()
    {
        $jwt = JWT::encode(['a' => 1], 'secret');

        self::assertSame(['a' => 1], JWT::decode('Bearer ' . $jwt, 'secret', true, JWT::HS256));
    }

    // -------------------------------------------------------------------------
    // Rejections
    // -------------------------------------------------------------------------

    public function testWrongKeyIsRejected()
    {
        $jwt = JWT::encode(['a' => 1], 'secret');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Signature verification failed');
        JWT::decode($jwt, 'other', true, JWT::HS256);
    }

    public function testUnexpectedAlgorithmIsRejected()
    {
        $jwt = JWT::encode(['a' => 1], 'secret', JWT::HS512);

        $this->expectExceptionMessage('Unexpected algorithm');
        JWT::decode($jwt, 'secret', true, JWT::HS256);
    }

    public function testNoneAlgorithmIsNotSupported()
    {
        $jwt = self::b64('{"alg":"none"}') . '.' . self::b64('{"a":1}') . '.' . self::b64('x');

        $this->expectExceptionMessage('Algorithm not supported');
        JWT::decode($jwt, 'secret');
    }

    public function testExpiredTokenIsRejectedAfterLeeway()
    {
        JWT::$timestamp = 1000;
        $jwt = JWT::encode(['exp' => 980], 'secret');

        // Still inside the 30 s leeway
        self::assertSame(['exp' => 980], JWT::decode($jwt, 'secret', true, JWT::HS256));

        JWT::$timestamp = 1010;
        $this->expectExceptionMessage('Expired token');
        JWT::decode($jwt, 'secret', true, JWT::HS256);
    }

    public function testNotBeforeIsEnforced()
    {
        JWT::$timestamp = 1000;
        $jwt = JWT::encode(['nbf' => 2000], 'secret');

        $this->expectExceptionMessageMatches('/^Cannot handle token prior to/');
        JWT::decode($jwt, 'secret', true, JWT::HS256);
    }

    public function testVerifyFalseSkipsTheSignatureButNotTheClaims()
    {
        $jwt = JWT::encode(['a' => 1], 'secret');
        self::assertSame(['a' => 1], JWT::decode($jwt, 'any-non-empty-key', false));

        JWT::$timestamp = 1000;
        $this->expectExceptionMessage('Expired token');
        JWT::decode(JWT::encode(['exp' => 1], 'secret'), 'x', false);
    }

    public function testWrongNumberOfSegments()
    {
        $this->expectExceptionMessage('Wrong number of segments');
        JWT::decode('a.b', 'secret');
    }

    // -------------------------------------------------------------------------
    // Known bugs (see TODO.md)
    // -------------------------------------------------------------------------

    public function testHmacSignatureIsComparedWithStrictEqualityNotHashEquals()
    {
        // BUG: verify() compares HMAC signatures with === (timing leak) instead of hash_equals().
        $source = file_get_contents(__DIR__ . '/../src/JWT.php');

        self::assertStringContainsString('self::hmac($algo, $msg, $key) === $signature', $source);
        self::assertStringNotContainsString('hash_equals', $source);
    }

    public function testEs256SignatureIsDerEncodedNotRawRAndS()
    {
        // BUG: openssl_sign() returns a DER SEQUENCE; RFC 7518 requires 64 raw bytes (R||S) for ES256.
        [$private] = self::$ec;
        $signature = JWT::sign('msg', $private, JWT::ES256);

        self::assertNotSame(64, strlen($signature));
        self::assertSame("\x30", $signature[0]);
    }

    public function testEs256TokenFromAStandardLibraryIsRejected()
    {
        // BUG: a spec-compliant ES256 token (raw R||S signature) does not verify.
        [$private, $public] = self::$ec;
        $input = self::b64('{"typ":"JWT","alg":"ES256"}') . '.' . self::b64('{"a":1}');
        openssl_sign($input, $der, $private, OPENSSL_ALGO_SHA256);
        $jwt = $input . '.' . self::b64(self::derToRaw($der, 32));

        $this->expectExceptionMessage('Signature verification failed');
        JWT::decode($jwt, $public, true, JWT::ES256);
    }

    public function testDecodeWithoutExpectedAlgAcceptsHs256SignedWithTheRsaPublicKey()
    {
        // BUG: $expectedAlg is optional; without it the header alg is trusted, so the
        // public PEM becomes an HMAC secret (algorithm confusion).
        [, $public] = self::$rsa;
        $forged = JWT::encode(['admin' => true], $public, JWT::HS256);

        self::assertSame(['admin' => true], JWT::decode($forged, $public));
    }

    public function testEmptyPayloadCannotBeDecoded()
    {
        // BUG: parse() treats an empty payload array as an encoding error.
        $jwt = JWT::encode([], 'secret');

        $this->expectExceptionMessage('Invalid segment encoding');
        JWT::decode($jwt, 'secret', true, JWT::HS256);
    }
}
