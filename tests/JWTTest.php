<?php

use Pebble\Security\Exception;
use Pebble\Security\JWT;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    private static array $rsa = [];
    private static array $ec = [];
    private static array $ecByAlg = [];

    public static function setUpBeforeClass(): void
    {
        self::$rsa = self::keyPair(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::$ec = self::keyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::$ecByAlg = [
            JWT::ES256 => [self::$ec, OPENSSL_ALGO_SHA256, 32],
            JWT::ES384 => [self::keyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']), OPENSSL_ALGO_SHA384, 48],
            JWT::ES512 => [self::keyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']), OPENSSL_ALGO_SHA512, 66],
        ];
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

    /**
     * Converts a raw R||S ECDSA signature to DER, to check it with openssl_verify().
     */
    private static function rawToDer(string $raw): string
    {
        $der = '';
        foreach (str_split($raw, strlen($raw) / 2) as $int) {
            $int = ltrim($int, "\0");
            if ($int === '' || ord($int[0]) >= 0x80) $int = "\0" . $int;
            $der .= "\x02" . chr(strlen($int)) . $int;
        }

        return "\x30" . (strlen($der) >= 0x80 ? "\x81" : '') . chr(strlen($der)) . $der;
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

    public function testEsRoundTrip()
    {
        foreach (self::$ecByAlg as $alg => [[$private, $public]]) {
            $jwt = JWT::encode(['a' => 1], $private, $alg);

            self::assertSame(['a' => 1], JWT::decode($jwt, $public, true, $alg), $alg);
        }
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

    public function testNonStringAlgorithmIsNotSupported()
    {
        $jwt = self::b64('{"alg":["HS256"]}') . '.' . self::b64('{"a":1}') . '.' . self::b64('x');

        $this->expectExceptionMessage('Algorithm not supported');
        JWT::decode($jwt, 'secret');
    }

    public function testUpperCaseAlgHeaderIsIgnored()
    {
        $jwt = self::b64('{"ALG":"HS256"}') . '.' . self::b64('{"a":1}') . '.' . self::b64('x');

        $this->expectExceptionMessage('Empty algorithm');
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

    public function testZeroExpirationIsExpired()
    {
        JWT::$timestamp = 1000;
        $jwt = JWT::encode(['exp' => 0], 'secret');

        $this->expectExceptionMessage('Expired token');
        JWT::decode($jwt, 'secret', true, JWT::HS256);
    }

    public function testZeroNotBeforeAndIssuedAtAreAccepted()
    {
        JWT::$timestamp = 1000;
        $jwt = JWT::encode(['nbf' => 0, 'iat' => 0], 'secret');

        self::assertSame(['nbf' => 0, 'iat' => 0], JWT::decode($jwt, 'secret', true, JWT::HS256));
    }

    public function testNonNumericTimeClaimIsRejected()
    {
        JWT::$timestamp = 1000;

        foreach (['exp', 'nbf', 'iat'] as $name) {
            foreach (['tomorrow', '', true, false, [2000]] as $value) {
                try {
                    JWT::decode(JWT::encode([$name => $value], 'secret'), 'secret', true, JWT::HS256);
                    self::fail("$name = " . json_encode($value) . ' was accepted');
                } catch (\Pebble\Security\Exception $e) {
                    self::assertSame("Invalid claim {$name}", $e->getMessage());
                }
            }
        }
    }

    public function testNumericStringAndNullTimeClaims()
    {
        JWT::$timestamp = 1000;

        // Numeric strings are compared as numbers
        self::assertSame(['exp' => '2000'], JWT::decode(JWT::encode(['exp' => '2000'], 'secret'), 'secret', true, JWT::HS256));
        self::assertSame(['exp' => 2000.5], JWT::decode(JWT::encode(['exp' => 2000.5], 'secret'), 'secret', true, JWT::HS256));

        // null means "not set"
        self::assertSame(['exp' => null], JWT::decode(JWT::encode(['exp' => null], 'secret'), 'secret', true, JWT::HS256));

        $this->expectExceptionMessage('Expired token');
        JWT::decode(JWT::encode(['exp' => '1'], 'secret'), 'secret', true, JWT::HS256);
    }

    public function testUpperCaseClaimsAreNotTimeClaims()
    {
        JWT::$timestamp = 1000;
        $jwt = JWT::encode(['EXP' => 1, 'NBF' => 5000, 'IAT' => 5000], 'secret');

        self::assertSame(['EXP' => 1, 'NBF' => 5000, 'IAT' => 5000], JWT::decode($jwt, 'secret', true, JWT::HS256));
    }

    public function testVerifyFalseSkipsTheSignatureButNotTheClaims()
    {
        $jwt = JWT::encode(['a' => 1], 'secret');
        self::assertSame(['a' => 1], JWT::decode($jwt, 'any-non-empty-key', false));

        JWT::$timestamp = 1000;
        $this->expectExceptionMessage('Expired token');
        JWT::decode(JWT::encode(['exp' => 1], 'secret'), 'x', false);
    }

    public function testHmacSignatureIsComparedWithHashEquals()
    {
        $source = file_get_contents(__DIR__ . '/../src/JWT.php');

        self::assertStringContainsString('hash_equals(self::hmac($algo, $msg, $key), $signature)', $source);
    }

    public function testTamperedHmacSignatureIsRejected()
    {
        $jwt = JWT::encode(['a' => 1], 'secret');
        $jwt[strlen($jwt) - 2] = $jwt[strlen($jwt) - 2] === 'A' ? 'B' : 'A';

        $this->expectExceptionMessage('Signature verification failed');
        JWT::decode($jwt, 'secret', true, JWT::HS256);
    }

    public function testEmptyPayloadRoundTrips()
    {
        $jwt = JWT::encode([], 'secret');

        self::assertSame([], JWT::decode($jwt, 'secret', true, JWT::HS256));
    }

    public function testNonJsonPayloadIsAnEncodingError()
    {
        $jwt = self::b64('{"alg":"HS256"}') . '.' . self::b64('not json') . '.' . self::b64('x');

        $this->expectExceptionMessage('Invalid segment encoding');
        JWT::decode($jwt, 'secret', true, JWT::HS256);
    }

    public function testWrongNumberOfSegments()
    {
        $this->expectExceptionMessage('Wrong number of segments');
        JWT::decode('a.b', 'secret');
    }

    // -------------------------------------------------------------------------
    // ECDSA signature format (RFC 7518 §3.4)
    // -------------------------------------------------------------------------

    public function testEsSignatureIsRawRAndS()
    {
        foreach (self::$ecByAlg as $alg => [[$private, $public], $algo, $size]) {
            for ($i = 0; $i < 20; $i++) {
                $signature = JWT::sign("msg $i", $private, $alg);

                self::assertSame(2 * $size, strlen($signature), $alg);
                self::assertSame(1, openssl_verify("msg $i", self::rawToDer($signature), $public, $algo), $alg);
            }
        }
    }

    public function testEs256TokenFromAStandardLibraryIsAccepted()
    {
        [$private, $public] = self::$ec;
        $input = self::b64('{"typ":"JWT","alg":"ES256"}') . '.' . self::b64('{"a":1}');
        openssl_sign($input, $der, $private, OPENSSL_ALGO_SHA256);
        $jwt = $input . '.' . self::b64(self::derToRaw($der, 32));

        self::assertSame(['a' => 1], JWT::decode($jwt, $public, true, JWT::ES256));
    }

    public function testLegacyDerEsTokenIsStillAccepted()
    {
        // Tokens signed before the switch to R||S carry the DER signature returned by openssl_sign()
        foreach (self::$ecByAlg as $alg => [[$private, $public], $algo]) {
            $input = self::b64('{"typ":"JWT","alg":"' . $alg . '"}') . '.' . self::b64('{"a":1}');
            openssl_sign($input, $der, $private, $algo);

            self::assertSame("\x30", $der[0]);
            self::assertSame(['a' => 1], JWT::decode($input . '.' . self::b64($der), $public, true, $alg), $alg);
        }
    }

    public function testTamperedEsSignatureIsRejected()
    {
        [$private, $public] = self::$ec;
        $signature = JWT::sign('msg', $private, JWT::ES256);
        $signature[10] = chr(ord($signature[10]) ^ 1);

        self::assertFalse(JWT::verify('msg', $signature, $public, JWT::ES256));
        self::assertFalse(JWT::verify('msg', random_bytes(64), $public, JWT::ES256));
    }

    public function testEsSignatureFromAnotherKeyIsRejected()
    {
        [$private] = self::keyPair(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        [, $public] = self::$ec;

        self::assertFalse(JWT::verify('msg', JWT::sign('msg', $private, JWT::ES256), $public, JWT::ES256));
    }

    // -------------------------------------------------------------------------
    // Lower-case algorithm names
    // -------------------------------------------------------------------------

    public function testLowerCaseAlgorithmIsEncodedUpperCase()
    {
        [$rsaPrivate, $rsaPublic] = self::$rsa;
        [[$ecPrivate, $ecPublic]] = self::$ecByAlg[JWT::ES256];

        foreach ([['hs256', 'secret', 'secret'], ['rs256', $rsaPrivate, $rsaPublic], ['es256', $ecPrivate, $ecPublic]] as [$alg, $private, $public]) {
            $jwt = JWT::encode(['a' => 1], $private, $alg);
            [, , , $header] = JWT::parse($jwt);

            self::assertSame(strtoupper($alg), $header['alg']);
            self::assertSame(['a' => 1], JWT::decode($jwt, $public, true, $alg));
            self::assertSame(['a' => 1], JWT::decode($jwt, $public, true, strtoupper($alg)));
        }
    }

    public function testLowerCaseAlgorithmInHeaderIsAccepted()
    {
        [$rsaPrivate, $rsaPublic] = self::$rsa;
        [[$ecPrivate, $ecPublic]] = self::$ecByAlg[JWT::ES256];

        foreach ([['hs256', 'secret', 'secret'], ['rs256', $rsaPrivate, $rsaPublic], ['es256', $ecPrivate, $ecPublic]] as [$alg, $private, $public]) {
            $msg = self::b64('{"typ":"JWT","alg":"' . $alg . '"}') . '.' . self::b64('{"a":1}');
            $jwt = $msg . '.' . self::b64(JWT::sign($msg, $private, strtoupper($alg)));

            foreach ([null, $alg, strtoupper($alg)] as $expected) {
                self::assertSame(['a' => 1], JWT::decode($jwt, $public, true, $expected));
            }
        }
    }

    public function testLowerCaseAlgorithmStillHasToMatchTheExpectedOne()
    {
        $msg = self::b64('{"alg":"hs512"}') . '.' . self::b64('{"a":1}');
        $jwt = $msg . '.' . self::b64(JWT::sign($msg, 'secret', JWT::HS512));

        $this->expectExceptionMessage('Unexpected algorithm');
        JWT::decode($jwt, 'secret', true, 'hs256');
    }

    // -------------------------------------------------------------------------
    // Key / algorithm binding
    // -------------------------------------------------------------------------

    /**
     * Decodes $jwt and returns [exception message, warnings].
     */
    private static function decodeFailure(string $jwt, string $key): array
    {
        $warnings = [];
        $message = null;
        set_error_handler(function ($no, $str) use (&$warnings) {
            $warnings[] = $str;
            return true;
        });

        try {
            JWT::decode($jwt, $key);
        } catch (Exception $ex) {
            $message = $ex->getMessage();
        } finally {
            restore_error_handler();
        }

        return [$message, $warnings];
    }

    public function testHs256SignedWithTheRsaPublicKeyIsRejectedWithoutExpectedAlg()
    {
        // Algorithm confusion: the public PEM used as HMAC secret
        [, $public] = self::$rsa;
        $forged = JWT::encode(['admin' => true], $public, JWT::HS256);

        self::assertSame(['Signature verification failed', []], self::decodeFailure($forged, $public));
    }

    public function testOpensslTokenWithAnHmacSecretIsRejectedWithoutWarning()
    {
        // Production incident: a user sent an RS*/ES* token to an HS* endpoint,
        // openssl_verify() raised "cannot be coerced into a public key"
        [$rsaPrivate] = self::$rsa;
        [[$ecPrivate]] = self::$ecByAlg[JWT::ES256];

        foreach ([JWT::encode(['a' => 1], $rsaPrivate, JWT::RS256), JWT::encode(['a' => 1], $ecPrivate, JWT::ES256)] as $jwt) {
            self::assertSame(['Signature verification failed', []], self::decodeFailure($jwt, 'secret'));
        }
    }

    public function testKeyOfAnotherTypeOrCurveIsRejected()
    {
        [$rsaPrivate, $rsaPublic] = self::$rsa;
        [[$p256Private, $p256Public]] = self::$ecByAlg[JWT::ES256];
        [[, $p521Public]] = self::$ecByAlg[JWT::ES512];

        $cases = [
            [JWT::sign('msg', $rsaPrivate, JWT::RS256), $p256Public, JWT::RS256],
            [JWT::sign('msg', $p256Private, JWT::ES256), $rsaPublic, JWT::ES256],
            [JWT::sign('msg', $p256Private, JWT::ES256), $p521Public, JWT::ES512],
            [JWT::sign('msg', $p256Private, JWT::ES256), $p256Public, JWT::ES512],
        ];

        foreach ($cases as [$signature, $key, $alg]) {
            self::assertFalse(JWT::verify('msg', $signature, $key, $alg));
        }
    }

    public function testCertificateIsAcceptedAsPublicKey()
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_x509_export(openssl_csr_sign(openssl_csr_new(['commonName' => 'test'], $key), null, $key, 1), $cert);
        openssl_pkey_export($key, $private);

        self::assertSame(['a' => 1], JWT::decode(JWT::encode(['a' => 1], $private, JWT::RS256), $cert, true, JWT::RS256));
    }

    // -------------------------------------------------------------------------
    // Short HMAC secrets
    // -------------------------------------------------------------------------

    /**
     * Runs $fn with the one-time deprecation re-armed and returns the deprecations raised
     */
    private static function deprecations(callable $fn): array
    {
        $flag = new ReflectionProperty(JWT::class, 'shortKeyWarned');
        $flag->setValue(null, false);
        $raised = [];
        set_error_handler(function ($no, $str) use (&$raised) {
            if ($no === E_USER_DEPRECATED) $raised[] = $str;
            return true;
        });

        try {
            $fn();
        } finally {
            restore_error_handler();
            $flag->setValue(null, true);
        }

        return $raised;
    }

    public function testShortHmacSecretIsDeprecatedOnce()
    {
        $raised = self::deprecations(function () {
            JWT::decode(JWT::encode(['a' => 1], 'secret'), 'secret', true, JWT::HS256);
            JWT::decode(JWT::encode(['a' => 1], 'secret', JWT::HS512), 'secret', true, JWT::HS512);
        });

        self::assertSame(['Pebble\\Security\\JWT: an HS256 secret shorter than 32 bytes is deprecated and will be rejected in the next major version'], $raised);
    }

    public function testShortHmacSecretStillWorks()
    {
        self::deprecations(function () use (&$payload) {
            $payload = JWT::decode(JWT::encode(['a' => 1], 'secret'), 'secret', true, JWT::HS256);
        });

        self::assertSame(['a' => 1], $payload);
    }

    public function testHmacSecretAsLongAsTheHashIsNotDeprecated()
    {
        $raised = self::deprecations(function () {
            JWT::decode(JWT::encode(['a' => 1], str_repeat('k', 32)), str_repeat('k', 32), true, JWT::HS256);
            JWT::decode(JWT::encode(['a' => 1], str_repeat('k', 48), JWT::HS384), str_repeat('k', 48), true, JWT::HS384);
            JWT::decode(JWT::encode(['a' => 1], str_repeat('k', 64), JWT::HS512), str_repeat('k', 64), true, JWT::HS512);
        });

        self::assertSame([], $raised);
    }

    public function testHs512SecretShorterThan64BytesIsDeprecated()
    {
        $raised = self::deprecations(function () {
            JWT::sign('msg', str_repeat('k', 32), JWT::HS512);
        });

        self::assertSame(['Pebble\\Security\\JWT: an HS512 secret shorter than 64 bytes is deprecated and will be rejected in the next major version'], $raised);
    }
}
