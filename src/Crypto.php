<?php

namespace Pebble\Security;

/**
 * Crypto
 *
 * @author mathieu
 */
class Crypto
{
    const METHOD = 'aes-256-cbc';

    private $method;

    // -------------------------------------------------------------------------

    public function __construct($method = null)
    {
        $this->method = $method ?: self::METHOD;
    }

    // -------------------------------------------------------------------------

    /**
     * @return static
     */
    public static function make($method = null): static
    {
        return new static($method);
    }

    /**
     * @param string $str
     * @param string $key
     * @return string
     */
    public function encode(string $str, string $key): string
    {
        $str = $str ?? '';

        $iv  = $this->iv($key);
        $ssl = openssl_encrypt($str, $this->method, $key, OPENSSL_RAW_DATA, $iv);

        return $ssl ? base64_encode($ssl) : '';
    }

    /**
     * @param string $str
     * @param string $key
     * @return string|null
     */
    public function decode(string $str, string $key): ?string
    {
        $str = $str ?? '';

        if (preg_match('/[^a-zA-Z0-9\/\+=]/', $str)) {
            return null;
        }

        $iv  = $this->iv($key);
        $dec = base64_decode($str);

        return openssl_decrypt($dec, $this->method, $key, OPENSSL_RAW_DATA, $iv) ?: null;
    }

    /**
     * Création du vecteur d'initialisation à partir de la clé
     *
     * @param string $key
     * @return string
     */
    private function iv(string $key): string
    {
        $iv_len = openssl_cipher_iv_length($this->method);
        return mb_substr(str_pad($key, $iv_len, '0'), 0, $iv_len);
    }

    // -------------------------------------------------------------------------
}

/* End of file */
