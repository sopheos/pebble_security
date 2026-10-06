<?php

namespace Pebble\Security;

/**
 * Hash
 *
 * @deprecated use Crypto
 */
class Hash
{
    // -------------------------------------------------------------------------

    /**
     * Hash a string to a specific length
     *
     * @deprecated use Crypto::hash()
     * @param string $string
     * @param int $length
     * @return string
     */
    public static function make($string, $length = 40)
    {
        return Crypto::hash((string) $string, (int) $length);
    }

    // -------------------------------------------------------------------------

    /**
     * Generate a salt string
     *
     * @deprecated use Crypto::salt()
     * @param int $length
     * @return string
     */
    public static function salt($length = 40)
    {
        return Crypto::salt((int) $length);
    }

    // -------------------------------------------------------------------------

    /**
     * Generates cryptographically secure pseudo-random string
     *
     * @deprecated use Crypto::random()
     * @param integer $length
     * @return string
     */
    public static function random(int $length = 40): string
    {
        return Crypto::random($length);
    }

    /**
     * Generate a UUID (v7)
     *
     * @deprecated use Crypto::uuid()
     * @return string
     */
    public static function uuid()
    {
        return Crypto::uuid();
    }

    /**
     * Generate a cryptographically secure numeric OTP
     *
     * @deprecated use Crypto::otp()
     * @param integer $len
     * @return string
     */
    public static function otp(int $len = 6): string
    {
        return Crypto::otp($len);
    }

    // -------------------------------------------------------------------------

    /**
     * Generate an email hash
     *
     * @deprecated use Crypto::email()
     * @param string $email
     * @return string|null
     */
    public static function email(string $email): ?string
    {
        return Crypto::email($email);
    }

    // -------------------------------------------------------------------------
}

/* End of file */
