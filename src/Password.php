<?php

namespace Pebble\Security;

/**
 * Password
 *
 * @deprecated use Crypto::passwordHash() and Crypto::passwordVerify()
 * @author mathieu
 */
class Password
{

    private mixed $cost = null;

    // -------------------------------------------------------------------------

    /**
     * No effect: password_hash() ignores the salt option since PHP 8.0
     *
     * @deprecated no effect
     * @param string $salt
     * @return \Pebble\Security\Password
     */
    public function setSalt($salt)
    {
        return $this;
    }

    // -------------------------------------------------------------------------

    /**
     * Set a cost for password hash
     *
     * @deprecated pass the cost to Crypto::passwordHash()
     * @param int $cost
     * @return \Pebble\Security\Password
     */
    public function setCost($cost)
    {
        if (($cost = (int) $cost)) {
            $this->cost = $cost;
        }

        return $this;
    }

    // -------------------------------------------------------------------------

    /**
     * Return a password hash
     *
     * @deprecated use Crypto::passwordHash()
     * @param string $password
     * @return string
     */
    public function hash($password)
    {
        return Crypto::passwordHash((string) $password, $this->cost);
    }

    // -------------------------------------------------------------------------

    /**
     * Verify if a password and a hash corresponds
     *
     * @deprecated use Crypto::passwordVerify()
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    public function verify($password, $hash)
    {
        return Crypto::passwordVerify((string) $password, (string) $hash);
    }

    // -------------------------------------------------------------------------
}

/* End of file */
