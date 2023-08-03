<?php

namespace Pebble\Security;

/**
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 */
class JWT
{

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static $leeway = 30;

    /**
     * Allow the current timestamp to be specified.
     * Useful for fixing a value within unit testing.
     *
     * Will default to PHP time() value if null.
     */
    public static $timestamp = null;

    /**
     * Supported algorithm for HMAC
     */
    public static $algs = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512'
    ];

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string $jwt The JWT
     * @param string|null $key  The secret key
     * @param BOOL $verify Don't skip verification process
     * @return object The JWT's payload as a PHP object
     * @throws Exception Provided JWT was invalid
     */
    public static function decode($jwt, $key)
    {
        $timestamp = is_null(static::$timestamp) ? time() : static::$timestamp;

        if (empty($key)) {
            throw new Exception('Key may not be empty');
        }

        if (!is_string($jwt)) {
            throw new Exception('Wrong number of segments');
        }

        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new Exception('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;

        if (($header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64))) === null) {
            throw new Exception('Invalid segment encoding');
        }

        if (($payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyb64))) === null) {
            throw new Exception('Invalid segment encoding');
        }

        if (empty($header->alg)) {
            throw new Exception('Empty algorithm');
        }

        if (empty(static::$algs[$header->alg])) {
            throw new Exception('Algorithm not supported');
        }

        $sig = JWT::urlsafeB64Decode($cryptob64);
        if ($sig != JWT::sign("$headb64.$bodyb64", $key, $header->alg)) {
            throw new Exception('Signature verification failed');
        }

        // Check if the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload->nbf) && $payload->nbf > ($timestamp + static::$leeway)) {
            throw new Exception('Cannot handle token prior to ' . date('c', $payload->nbf));
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload->iat) && $payload->iat > ($timestamp + static::$leeway)) {
            throw new Exception('Cannot handle token prior to ' . date('c', $payload->iat));
        }

        // Check if this token has expired.
        if (isset($payload->exp) && ($timestamp - static::$leeway) >= $payload->exp) {
            throw new Exception('Expired token');
        }

        return $payload;
    }

    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array $payload PHP object or array
     * @param string       $key     The secret key
     * @param string       $algo    The signing algorithm. Supported
     *                              algorithms are 'HS256', 'HS384' and 'HS512'
     * @return string
     */
    public static function encode($payload, $key, $algo = 'HS256')
    {
        $header = ['typ' => 'JWT', 'alg' => $algo];

        $segments      = [];
        $segments[]    = JWT::urlsafeB64Encode(JWT::jsonEncode($header));
        $segments[]    = JWT::urlsafeB64Encode(JWT::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature  = JWT::sign($signing_input, $key, $algo);
        $segments[] = JWT::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $msg The message to sign
     * @param string $key The secret key
     * @param string $alg The signing algorithm. Supported
     *                       algorithms are 'HS256', 'HS384' and 'HS512'
     *
     * @return string An encrypted message
     * @throws Exception
     */
    public static function sign($msg, $key, $alg = 'HS256')
    {
        if (empty(static::$algs[$alg])) {
            throw new Exception('Algorithm not supported');
        }

        return hash_hmac(static::$algs[$alg], $msg, $key, true);
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     * @return object Object representation of JSON string
     * @throws Exception
     */
    public static function jsonDecode($input)
    {
        $obj   = json_decode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } else if ($obj === null && $input !== 'null') {
            throw new Exception('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Encode a PHP object into a JSON string.
     *
     * @param object|array $input A PHP object or array
     * @return string JSON representation of the PHP object or array
     * @throws Exception
     */
    public static function jsonEncode($input)
    {
        $json  = json_encode($input);
        if (function_exists('json_last_error') && $errno = json_last_error()) {
            JWT::handleJsonError($errno);
        } else if ($json === 'null' && $input !== null) {
            throw new Exception('Null result with non-null input');
        }
        return $json;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = mb_strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input  .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     * @return void
     */
    private static function handleJsonError($errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH     => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX    => 'Syntax error, malformed JSON'
        );
        throw new Exception(
            isset($messages[$errno]) ? $messages[$errno] : 'Unknown JSON error: ' . $errno
        );
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
}
