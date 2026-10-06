<?php

namespace Pebble\Security;

/**
 * Crypto
 *
 * @author mathieu
 */
class Crypto
{
    /**
     * Authenticated cipher used by encrypt()
     */
    const ENCODER = 'aes-256-gcm';

    /**
     * Legacy cipher, only used to read old ciphertexts
     */
    private const LEGACY_METHOD = 'aes-256-cbc';

    const TAG_LENGTH = 16;

    /**
     * Available algorythm
     *
     * @var array
     */
    private static $algos = [
        32  => 'md5',
        40  => 'sha1',
        64  => 'sha256',
        128 => 'sha512',
    ];

    // -------------------------------------------------------------------------

    public static function create(): static
    {
        return new static;
    }

    /**
     * @deprecated use new Crypto()
     * @param string|null $method obsolete and ignored, kept for compatibility
     * @return static
     */
    public static function make($method = null)
    {
        return new static($method);
    }

    // -------------------------------------------------------------------------

    /**
     * Hash a string to a specific length
     *
     * @param string $string
     * @param int $length
     * @return string
     */
    public static function hash(string $string, int $length = 40): string
    {
        if (!isset(self::$algos[$length])) {
            $length = 40;
        }

        return hash(self::$algos[$length], $string, false);
    }

    /**
     * Generate a salt string
     *
     * @param int $length
     * @return string
     */
    public static function salt(int $length = 40): string
    {
        return self::hash(random_bytes($length), $length);
    }

    /**
     * Generates cryptographically secure pseudo-random string
     *
     * @param integer $length
     * @return string
     */
    public static function random(int $length = 40): string
    {
        $bytes = random_bytes((int) ceil($length / 2));
        return substr(bin2hex($bytes), 0, $length);
    }

    /**
     * Generate a UUID (v7)
     * 36 characters : 32 hexadecimal numbers and 4 dashes
     * 48-bit Unix timestamp (ms) + 74 random bits, lexicographically sortable
     * Exemple : 0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b
     * https://www.rfc-editor.org/rfc/rfc9562
     *
     * @return string 36 characters
     */
    public static function uuid(): string
    {
        $time = str_pad(dechex((int) (microtime(true) * 1000)), 12, '0', STR_PAD_LEFT);
        $rand = random_bytes(10);
        $rand[0] = chr((ord($rand[0]) & 0x0f) | 0x70); // version 7
        $rand[2] = chr((ord($rand[2]) & 0x3f) | 0x80); // variant RFC 9562

        $hex = $time . bin2hex($rand);

        return vsprintf('%s-%s-%s-%s-%s', [
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20),
        ]);
    }

    /**
     * Generate a cryptographically secure numeric OTP
     *
     * @param integer $len 1 to 18 digits
     * @return string
     * @throws \ValueError
     */
    public static function otp(int $len = 6): string
    {
        if ($len < 1 || $len > 18) {
            throw new \ValueError('OTP length must be between 1 and 18');
        }

        return str_pad((string) random_int(0, 10 ** $len - 1), $len, '0', STR_PAD_LEFT);
    }

    /**
     * Generate an email hash
     * Unkeyed sha1: not designed to resist a dictionary attack,
     * a common email can be recovered from its hash.
     *
     * @param string $email
     * @return string|null
     */
    public static function email(string $email): ?string
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return null;
        }

        [$name, $domain] = explode('@', $email);
        $domain = explode('.', $domain);
        $tld = array_pop($domain);
        $domain = implode('.', $domain);

        return self::hash($name) . '@' . self::hash($domain) . '.' . $tld;
    }

    // -------------------------------------------------------------------------

    /**
     * Return a password hash
     */
    public static function passwordHash(string $password, ?int $cost = null): string
    {
        $options = [];

        if ($cost) {
            $options['cost'] = $cost;
        }

        return password_hash($password, PASSWORD_BCRYPT, $options);
    }

    /**
     * Verify if a password and a hash corresponds
     */
    public static function passwordVerify(string $password, string $hash): bool
    {
        if ($password === '' || $hash === '') {
            return false;
        }

        return password_verify($password, $hash);
    }

    // -------------------------------------------------------------------------

    /**
     * Encrypt with aes-256-gcm: base64(iv . tag . ciphertext)
     *
     * @param string $str
     * @param string $key
     * @return string
     */
    public function encrypt(string $str, string $key): string
    {
        $iv  = random_bytes(openssl_cipher_iv_length(self::ENCODER));
        $ssl = openssl_encrypt($str, self::ENCODER, self::key($key), OPENSSL_RAW_DATA, $iv, $tag);

        return $ssl === false ? '' : base64_encode($iv . $tag . $ssl);
    }

    /**
     * Decrypt a ciphertext produced by encrypt().
     * Legacy ciphertexts (aes-256-cbc, key-derived IV) are still readable.
     *
     * @param string $str
     * @param string $key
     * @return string|null null if the ciphertext or the key is invalid
     */
    public function decrypt(string $str, string $key): ?string
    {
        if (preg_match('/[^a-zA-Z0-9\/\+=]/', $str)) {
            return null;
        }

        $raw = base64_decode($str, true);

        if ($raw === false) {
            return null;
        }

        $dec = $this->decryptAead($raw, $key);

        // A CBC ciphertext is always a multiple of the block size
        if ($dec === null && strlen($raw) % 16 === 0) {
            $dec = $this->decryptLegacy($raw, $key);
        }

        return $dec;
    }

    /**
     * @deprecated use encrypt()
     * @param string $str
     * @param string $key
     * @return string
     */
    public function encode(string $str, string $key): string
    {
        return $this->encrypt($str, $key);
    }

    /**
     * @deprecated use decrypt()
     * @param string $str
     * @param string $key
     * @return string|null
     */
    public function decode(string $str, string $key): ?string
    {
        return $this->decrypt($str, $key);
    }

    // -------------------------------------------------------------------------

    /**
     * @param string $raw
     * @param string $key
     * @return string|null
     */
    private function decryptAead(string $raw, string $key): ?string
    {
        $ivLen = openssl_cipher_iv_length(self::ENCODER);

        if (strlen($raw) < $ivLen + self::TAG_LENGTH) {
            return null;
        }

        $iv  = substr($raw, 0, $ivLen);
        $tag = substr($raw, $ivLen, self::TAG_LENGTH);
        $ssl = substr($raw, $ivLen + self::TAG_LENGTH);
        $dec = openssl_decrypt($ssl, self::ENCODER, self::key($key), OPENSSL_RAW_DATA, $iv, $tag);

        return $dec === false ? null : $dec;
    }

    /**
     * Read ciphertexts produced before the switch to aes-256-gcm
     *
     * @deprecated remove once legacy ciphertexts have been rewritten
     * @param string $raw
     * @param string $key
     * @return string|null
     */
    private function decryptLegacy(string $raw, string $key): ?string
    {
        // Rebuild the legacy IV: the first 16 characters of the key, truncated to bytes as openssl did
        $ivLen = openssl_cipher_iv_length(self::LEGACY_METHOD);
        $iv = substr(mb_substr(str_pad($key, $ivLen, '0'), 0, $ivLen), 0, $ivLen);
        $dec = openssl_decrypt($raw, self::LEGACY_METHOD, $key, OPENSSL_RAW_DATA, $iv);

        return $dec === false ? null : $dec;
    }

    /**
     * Derive a 32-byte key
     *
     * @param string $key
     * @return string
     */
    private static function key(string $key): string
    {
        return hash('sha256', $key, true);
    }

    // -------------------------------------------------------------------------
}

/* End of file */
