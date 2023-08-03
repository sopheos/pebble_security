<?php

namespace Pebble\Security;

class TokenException extends \Exception
{
    /**
     * @return \static
     */
    public static function required()
    {
        return new static('token_required');
    }

    /**
     * @return \static
     */
    public static function invalid()
    {
        return new static('token_invalid');
    }
}
