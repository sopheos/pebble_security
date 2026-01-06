<?php

namespace Pebble\Security;

/**
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 */
class JWT
{
    const HS256 = 'HS256';
    const HS384 = 'HS384';
    const HS512 = 'HS512';
    const RS256 = 'RS256';
    const RS384 = 'RS384';
    const RS512 = 'RS512';
    const ES256 = 'ES256';
    const ES384 = 'ES384';
    const ES512 = 'ES512';

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static int $leeway = 30;

    /**
     * Allow the current timestamp to be specified.
     * Useful for fixing a value within unit testing.
     *
     * Will default to PHP time() value if null.
     */
    public static int $timestamp = 0;

    /**
     * Supported algorithm for HMAC
     */
    private static $algs = [
        self::HS256 => 'sha256',
        self::HS384 => 'sha384',
        self::HS512 => 'sha512',
        self::RS256 => OPENSSL_ALGO_SHA256,
        self::RS384 => OPENSSL_ALGO_SHA384,
        self::RS512 => OPENSSL_ALGO_SHA512,
        self::ES256 => OPENSSL_ALGO_SHA256,
        self::ES384 => OPENSSL_ALGO_SHA384,
        self::ES512 => OPENSSL_ALGO_SHA512,
    ];

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param array $payload Payload
     * @param string $key The secret key
     * @param string $algo The signing algorithm.
     * @return string
     */
    public static function encode(array $payload, string $key, string $algo = self::HS256)
    {
        $header = ['typ' => 'JWT', 'alg' => $algo];

        $headb64 = self::urlsafeB64Encode(self::jsonEncode($header));
        $bodyb64 = self::urlsafeB64Encode(self::jsonEncode($payload));

        $signature  = self::sign("{$headb64}.{$bodyb64}", $key, $algo);
        $cryptob64 = self::urlsafeB64Encode($signature);

        return "{$headb64}.{$bodyb64}.{$cryptob64}";
    }

    /**
     * Decodes a JWT string into a PHP array.
     *
     * @param string $jwt The JWT
     * @param string|null $key  The secret key
     * @param bool $verify If false, skip verification process
     * @return object The JWT's payload as a PHP array
     * @throws Exception Provided JWT was invalid
     */
    public static function decode(string $jwt, string $key, bool $verify = true)
    {
        if (! $key) {
            throw new Exception('Key may not be empty');
        }

        list($headb64, $bodyb64, $header, $payload, $sign) = self::parse($jwt);

        if (! ($alg = self::a($header, 'alg'))) {
            throw new Exception('Empty algorithm');
        }

        if (! self::a(self::$algs, $alg)) {
            throw new Exception('Algorithm not supported');
        }

        // Check signature
        if ($verify && !self::verify("{$headb64}.{$bodyb64}", $sign, $key, $alg)) {
            throw new Exception('Signature verification failed');
        }

        $timestamp = self::$timestamp ?: time();

        // Check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (($nbf = self::a($payload, 'nbf')) && $nbf > ($timestamp + self::$leeway)) {
            throw new Exception('Cannot handle token prior to ' . date('c', $nbf));
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (($iat = self::a($payload, 'iat')) && $iat > ($timestamp + self::$leeway)) {
            throw new Exception('Cannot handle token prior to ' . date('c', $iat));
        }

        // Check if this token has expired.
        if (($exp = self::a($payload, 'exp')) && ($timestamp - self::$leeway) >= $exp) {
            throw new Exception('Expired token');
        }

        return $payload;
    }

    /**
     * Parse JWT string
     *
     * @param string $jwt
     * @return array
     */
    public static function parse(string $jwt): array
    {
        $tks = explode('.', self::getBearerToken($jwt));

        if (count($tks) != 3) {
            throw new Exception('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;

        if (!($header = self::jsonDecode(self::urlsafeB64Decode($headb64)))) {
            throw new Exception('Invalid segment encoding');
        }

        if (!($payload = self::jsonDecode(self::urlsafeB64Decode($bodyb64)))) {
            throw new Exception('Invalid segment encoding');
        }

        if (!($signature = self::urlsafeB64Decode($cryptob64))) {
            throw new Exception('Invalid segment encoding');
        }

        return [$headb64, $bodyb64, $cryptob64, $header, $payload, $signature];
    }

    /**
     * Get access token from header
     *
     * @param string $token
     * @return string|null
     */
    public static function getBearerToken(string $token): string
    {
        $matches = [];

        if (preg_match('/bearer\s((.*)\.(.*)\.(.*))/i', $token, $matches)) {
            return $matches[1];
        }

        return $token;
    }

    /**
     * Sign a string
     *
     * @param string $msg The message to sign
     * @param string $key The secret key
     * @param string $alg The signing algorithm. Supported
     *                       algorithms are 'HS256', 'HS384' and 'HS512'
     *
     * @return string An encrypted message
     * @throws Exception
     */
    public static function sign($msg, $key, $alg = self::HS256)
    {
        if (! ($algo = self::a(self::$algs, $alg))) {
            throw new Exception('Algorithm not supported');
        }

        return hash_hmac(static::$algs[$alg], $msg, $key, true);
    }

    /**
     * Verify a signature
     *
     * @param string $data
     * @param string $signature
     * @param string $key
     * @param string $alg
     * @return boolean
     * @throws Exception
     */
    public static function verify(string $data, string $signature, string $key, string $alg = self::HS256): bool
    {
        if (! ($algo = self::a(self::$algs, $alg))) {
            throw new Exception('Algorithm not supported');
        }

        if (str_contains($alg, 'HS')) {
            return hash_hmac($algo, $data, $key, true) === $signature;
        }

        return openssl_verify($data, $signature, $key, $algo) === 1;
    }

    private static function jsonDecode(string $input): array
    {
        $out = json_decode($input, true);
        return is_array($out) ? $out : [];
    }

    private static function jsonEncode(array $input): string
    {
        return json_encode($input);
    }

    private static function urlsafeB64Decode(string $input): string
    {
        $remainder = mb_strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input  .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    private static function urlsafeB64Encode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    private static function a(array $input, string $key): mixed
    {
        return $input[$key] ?? $input[mb_strtoupper($key)] ?? null;
    }
}
