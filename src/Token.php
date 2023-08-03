<?php

namespace Pebble\Security;

/**
 * Token
 *
 * Token system tools
 */
class Token
{
    private string $url;
    private string $key;
    private string $alg;
    private ?string $proof = null;
    private ?string $hash = null;
    private string $uuid = '';
    private $payload = [];

    // -------------------------------------------------------------------------

    /**
     * @param string $url
     * @param string $key
     * @param string $alg
     * @param string|null $proof
     */
    public function __construct(string $url, string $key, string $alg, ?string $proof = null)
    {
        $this->url = $url;
        $this->key = $key;
        $this->alg = $alg;
        $this->proof = $proof;

        if ($proof) {
            $this->hash = sha1($proof);
        }

        $this->init();
    }

    /**
     * @param array $payload
     * @return static
     */
    public function init(array $payload = []): static
    {
        $this->uuid = $payload['uuid'] ?? Hash::uuid();
        $this->payload = $payload;
        $this->add('uuid', $this->uuid);
        $this->add('hash', $this->hash);

        return $this;
    }

    /**
     * @param string $name
     * @param mixed $value
     * @return static
     */
    public function add(string $name, $value): static
    {
        if ($value === null) {
            if (array_key_exists($name, $this->payload)) {
                unset($this->payload[$name]);
            }
        } else {
            $this->payload[$name] = $value;
        }

        return $this;
    }

    /**
     * @param string $name
     * @return static
     */
    public function del(string $name): static
    {
        return $this->add($name, null);
    }

    // -------------------------------------------------------------------------
    // Getter
    // -------------------------------------------------------------------------

    /**
     * @return string
     */
    public function url(): string
    {
        return $this->url;
    }

    /**
     * @return string
     */
    public function key(): string
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function alg(): string
    {
        return $this->alg;
    }

    /**
     * @return string
     */
    public function uuid(): string
    {
        return $this->uuid;
    }

    /**
     * @return string|null
     */
    public function proof(): ?string
    {
        return $this->proof;
    }

    /**
     * @return string|null
     */
    public function hash(): ?string
    {
        return $this->hash;
    }

    /**
     * @return array
     */
    public function payload(): array
    {
        return $this->payload;
    }

    /**
     * @param string $name
     * @param mixed $default
     * @return mixed
     */
    public function get(string $name, mixed $default = null): mixed
    {
        return $this->payload[$name] ?? $default;
    }

    // -------------------------------------------------------------------------

    /**
     * @param string $token
     * @return static
     */
    public function import(string $token): static
    {
        // Token is required
        if (!$token) {
            throw TokenException::required();
        }

        // Parse the token
        $token = self::parseToken($token);

        // Decodes the token
        try {
            $data = JWT::decode($token, $this->key);
        } catch (\Exception $ex) {
            throw TokenException::invalid();
        }

        if ($this->hash && $this->hash !== ($data->hash ?? null)) {
            throw TokenException::invalid();
        }

        $this->init((array) $data);

        return $this;
    }

    /**
     * @param integer $exp
     */
    public function generate(int $exp = 0): string
    {
        $now = time();

        $this->add('iat', $now);

        if ($exp) {
            $this->add('exp', $now + $exp);
        }

        return JWT::encode($this->payload, $this->key, $this->alg);
    }

    // -------------------------------------------------------------------------

    /**
     * Parse a token
     *
     * @param string $token
     * @return string
     */
    public static function parseToken(string $token): string
    {
        $matches = [];

        if (preg_match('/bearer\s((.*)\.(.*)\.(.*))/i', $token, $matches)) {
            return $matches[1];
        }

        return $token;
    }

    // -------------------------------------------------------------------------
}
