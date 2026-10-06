<?php

namespace Pebble\Security;

/**
 * JSON Web Token implementation, based on RFC 7519 (JWT) and RFC 7518 (JWA):
 * https://www.rfc-editor.org/rfc/rfc7519
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
     * Supported algorithms (HMAC, RSA, ECDSA): hash_hmac() algo or openssl constant
     */
    private static array $algs = [
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
     * ECDSA: size in bytes of R and S in a raw R||S signature (RFC 7518 §3.4)
     */
    private static array $ecSizes = [
        self::ES256 => 32,
        self::ES384 => 48,
        self::ES512 => 66,
    ];

    /**
     * Set once the short HMAC secret deprecation has been raised
     */
    private static bool $shortKeyWarned = false;

    /**
     * ECDSA: curve expected for each algorithm (RFC 7518 §3.4)
     */
    private static array $ecCurves = [
        self::ES256 => 'prime256v1',
        self::ES384 => 'secp384r1',
        self::ES512 => 'secp521r1',
    ];

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param array $payload Payload
     * @param string $key The secret key
     * @param string $algo The signing algorithm.
     * @param string $keyId kid
     * @param array $head An array with header elements to attach
     *
     * @return string
     */
    public static function encode(
        array $payload,
        string $key,
        string $algo = self::HS256,
        ?string $keyId = null,
        ?array $head = null
    ) {
        $header = ['typ' => 'JWT', 'alg' => $algo = self::alg($algo)];

        if ($keyId) {
            $header['kid'] = $keyId;
        }

        if ($head) {
            $header = array_merge($header, $head);
        }

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
     * @param string|null $expectedAlg If set, reject tokens whose header alg differs
     * @return array The JWT's payload as a PHP array
     * @throws Exception Provided JWT was invalid
     */
    public static function decode(string $jwt, string $key, bool $verify = true, ?string $expectedAlg = null): array
    {
        if (! $key) {
            throw new Exception('Key may not be empty');
        }

        list($headb64, $bodyb64,, $header, $payload, $sign) = self::parse($jwt);

        // Header parameters and claims are case-sensitive (RFC 7515 §4, RFC 7519 §4): only lower-case names are read

        if (! ($alg = $header['alg'] ?? null)) {
            throw new Exception('Empty algorithm');
        }

        if (! is_string($alg) || ! isset(self::$algs[$alg = self::alg($alg)])) {
            throw new Exception('Algorithm not supported');
        }

        // Never trust the header alg: prevents algorithm confusion attacks
        if ($expectedAlg && $alg !== self::alg($expectedAlg)) {
            throw new Exception('Unexpected algorithm');
        }

        // Check signature
        if ($verify && !self::verify("{$headb64}.{$bodyb64}", $sign, $key, $alg)) {
            throw new Exception('Signature verification failed');
        }

        $timestamp = self::$timestamp ?: time();

        // Check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (($nbf = self::numericDate($payload, 'nbf')) !== null && $nbf > ($timestamp + self::$leeway)) {
            throw new Exception('Cannot handle token prior to ' . date('c', (int) $nbf));
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (($iat = self::numericDate($payload, 'iat')) !== null && $iat > ($timestamp + self::$leeway)) {
            throw new Exception('Cannot handle token prior to ' . date('c', (int) $iat));
        }

        // Check if this token has expired.
        if (($exp = self::numericDate($payload, 'exp')) !== null && ($timestamp - self::$leeway) >= $exp) {
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

        // An empty payload is valid, only invalid JSON is rejected
        if (!is_array($payload = json_decode(self::urlsafeB64Decode($bodyb64), true))) {
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
     * @return string
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
     * @param string $alg The signing algorithm
     * @return string An encrypted message
     * @throws Exception
     */
    public static function sign($msg, $key, $alg = self::HS256)
    {
        if (! ($algo = self::$algs[$alg = self::alg($alg)] ?? null)) {
            throw new Exception('Algorithm not supported');
        }

        if (self::isHmac($alg)) {
            return self::hmac($algo, $msg, $key);
        }

        $signature = '';
        if (!openssl_sign($msg, $signature, $key, $algo)) {
            throw new Exception('Error signing the JWT');
        }

        // openssl returns DER, JWS requires raw R||S
        if (($size = self::$ecSizes[$alg] ?? null)) {
            $signature = self::derToRaw($signature, $size);
        }

        return $signature;
    }

    /**
     * Verify a signature
     *
     * @param string $msg
     * @param string $signature
     * @param string $key
     * @param string $alg
     * @return boolean
     * @throws Exception
     */
    public static function verify(string $msg, string $signature, string $key, string $alg = self::HS256): bool
    {
        if (! ($algo = self::$algs[$alg = self::alg($alg)] ?? null)) {
            throw new Exception('Algorithm not supported');
        }

        // The key decides the algorithm family, never the token header:
        // a public PEM is not an HMAC secret, and an HMAC secret is not an openssl key
        if (self::isHmac($alg)) {
            return !self::isPem($key) && hash_equals(self::hmac($algo, $msg, $key), $signature);
        }

        if (!self::isKeyOf($key, $alg)) {
            return false;
        }

        if (($size = self::$ecSizes[$alg] ?? null) && strlen($signature) === 2 * $size) {
            if (openssl_verify($msg, self::rawToDer($signature), $key, $algo) === 1) {
                return true;
            }
        }

        // RSA, or ECDSA signature in DER issued before the switch to R||S
        // @deprecated DER fallback: remove once legacy ES* tokens have expired
        return openssl_verify($msg, $signature, $key, $algo) === 1;
    }

    /**
     * Convert a DER ECDSA signature (SEQUENCE of two INTEGER) to raw R||S
     *
     * @param string $der
     * @param int $size
     * @return string
     * @throws Exception
     */
    private static function derToRaw(string $der, int $size): string
    {
        $offset = 0;

        if (self::derRead($der, $offset, 0x30) === null) {
            throw new Exception('Invalid ECDSA signature');
        }

        $raw = '';

        foreach ([0, 1] as $i) {
            $int = self::derRead($der, $offset, 0x02);

            if ($int === null) {
                throw new Exception('Invalid ECDSA signature');
            }

            $raw .= str_pad(ltrim($int, "\0"), $size, "\0", STR_PAD_LEFT);
        }

        return $raw;
    }

    /**
     * Convert a raw R||S ECDSA signature to DER
     *
     * @param string $raw
     * @return string
     */
    private static function rawToDer(string $raw): string
    {
        $der = '';

        foreach (str_split($raw, intdiv(strlen($raw), 2)) as $int) {
            $int = ltrim($int, "\0");

            // INTEGER is signed: keep it positive
            if ($int === '' || ord($int[0]) > 0x7f) {
                $int = "\0" . $int;
            }

            $der .= "\x02" . self::derLength(strlen($int)) . $int;
        }

        return "\x30" . self::derLength(strlen($der)) . $der;
    }

    /**
     * Read a DER element of the expected tag, return its content and move the offset.
     * A SEQUENCE is entered: the offset points to its first child.
     *
     * @param string $der
     * @param int $offset
     * @param int $tag
     * @return string|null
     */
    private static function derRead(string $der, int &$offset, int $tag): ?string
    {
        if ($offset + 2 > strlen($der) || ord($der[$offset]) !== $tag) {
            return null;
        }

        $len = ord($der[$offset + 1]);
        $offset += 2;

        // Long form: 0x81 followed by one length byte (enough for ES512)
        if ($len === 0x81) {
            if ($offset >= strlen($der)) return null;
            $len = ord($der[$offset++]);
        } elseif ($len > 0x7f) {
            return null;
        }

        if ($offset + $len > strlen($der)) {
            return null;
        }

        $content = substr($der, $offset, $len);

        if ($tag !== 0x30) {
            $offset += $len;
        }

        return $content;
    }

    private static function derLength(int $len): string
    {
        return $len > 0x7f ? "\x81" . chr($len) : chr($len);
    }

    private static function jsonDecode(string $input): array
    {
        $out = json_decode($input, true);
        return is_array($out) ? $out : [];
    }

    private static function jsonEncode(array $input): string
    {
        return json_encode($input, JSON_UNESCAPED_SLASHES);
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

    /**
     * Reads a time claim. Absent or null means "not set"; any other value must be
     * a number (numeric strings are accepted), so 0 is a real date, not "not set".
     *
     * @throws Exception The claim is not a number
     */
    private static function numericDate(array $payload, string $name): int|float|null
    {
        if (($value = $payload[$name] ?? null) === null) return null;
        if (is_bool($value) || !is_numeric($value)) throw new Exception("Invalid claim {$name}");
        return $value + 0;
    }

    /**
     * Algorithm names are matched case-insensitively: 'hs256' is HS256
     */
    private static function alg(string $alg): string
    {
        return strtoupper($alg);
    }

    private static function isHmac(string $alg)
    {
        return str_contains($alg, 'HS');
    }

    private static function isPem(string $key): bool
    {
        return str_contains($key, '-----BEGIN');
    }

    /**
     * Whether $key is a public key (or certificate) matching $alg: RSA for RS*, the right curve for ES*
     */
    private static function isKeyOf(string $key, string $alg): bool
    {
        if (!($details = ($pkey = openssl_pkey_get_public($key)) ? openssl_pkey_get_details($pkey) : false)) {
            return false;
        }

        if (($curve = self::$ecCurves[$alg] ?? null)) {
            return $details['type'] === OPENSSL_KEYTYPE_EC && ($details['ec']['curve_name'] ?? null) === $curve;
        }

        return $details['type'] === OPENSSL_KEYTYPE_RSA;
    }

    private static function hmac(string $algo, string $msg, string $key): string
    {
        // RFC 7518 §3.2: the secret must be at least as long as the hash output. Warn once per process
        if (!self::$shortKeyWarned && strlen($key) < ($bytes = intdiv((int) substr($algo, 3), 8))) {
            self::$shortKeyWarned = true;
            trigger_error('Pebble\\Security\\JWT: an HS' . substr($algo, 3) . " secret shorter than {$bytes} bytes is deprecated and will be rejected in the next major version", E_USER_DEPRECATED);
        }

        return hash_hmac($algo, $msg, $key, true);
    }
}
