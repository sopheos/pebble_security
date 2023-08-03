<?php

namespace Pebble\Security;

/**
 * Description of Password
 *
 * @author mathieu
 */
class Password
{

    private $salt;
    private $cost;

    // -------------------------------------------------------------------------

    /**
     * Set a salt for password hash
     *
     * @param string $salt
     * @return \Pebble\Security\Password
     */
    public function setSalt($salt)
    {

        if ($salt) {
            $this->salt = $salt;
        }

        return $this;
    }

    // -------------------------------------------------------------------------

    /**
     * Set a cost for password hash
     *
     * @param int $cost
     * @return \Pebble\Security\Password
     */
    public function setCost($cost)
    {
        if ($cost) {
            $this->cost = $cost;
        }

        return $this;
    }

    // -------------------------------------------------------------------------

    /**
     * Return a password hash
     *
     * @param string $password
     * @return string
     */
    public function hash($password)
    {
        $options = [];

        if (isset($this->salt)) {
            $options['salt'] = $this->salt;
        }

        if (isset($this->cost)) {
            $options['cost'] = $this->cost;
        }

        return password_hash($password ?? "", PASSWORD_BCRYPT, $options);
    }

    // -------------------------------------------------------------------------

    /**
     * Verify if a password and a hash corresponds
     *
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    public function verify($password, $hash)
    {
        if (!$password || !$hash) {
            return false;
        }

        return password_verify($password, $hash);
    }

    // -------------------------------------------------------------------------
}

/* End of file */
