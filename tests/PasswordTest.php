<?php

use Pebble\Security\Password;
use PHPUnit\Framework\TestCase;

class PasswordTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Nominal
    // -------------------------------------------------------------------------

    public function testHashAndVerify()
    {
        $password = new Password();
        $hash = $password->hash('p4ssw0rd');

        // Default bcrypt cost depends on PHP (10 before 8.4, 12 since)
        self::assertMatchesRegularExpression('/^\$2y\$1[02]\$/', $hash);
        self::assertTrue($password->verify('p4ssw0rd', $hash));
        self::assertFalse($password->verify('wrong', $hash));
    }

    public function testCostIsApplied()
    {
        $hash = (new Password())->setCost(4)->hash('x');

        self::assertStringStartsWith('$2y$04$', $hash);
    }

    public function testEmptyPasswordOrHashNeverVerifies()
    {
        $password = new Password();

        self::assertFalse($password->verify('', $password->hash('')));
        self::assertFalse($password->verify('x', ''));
        self::assertFalse($password->verify(null, null));
    }

    // -------------------------------------------------------------------------
    // Known bugs (see TODO.md)
    // -------------------------------------------------------------------------

    public function testSaltIsIgnoredWithAWarning()
    {
        // BUG: setSalt() feeds the 'salt' option to password_hash(), ignored since PHP 8.0.
        $warnings = [];
        set_error_handler(function ($no, $str) use (&$warnings) {
            $warnings[] = $str;
            return true;
        });

        try {
            $hash = (new Password())->setCost(4)->setSalt(str_repeat('s', 22))->hash('x');
        } finally {
            restore_error_handler();
        }

        self::assertCount(1, $warnings);
        self::assertStringContainsString('"salt" option has been ignored', $warnings[0]);
        self::assertTrue(password_verify('x', $hash));
    }

    public function testPasswordZeroNeverVerifies()
    {
        // BUG: verify() starts with `!$password`, so the password '0' is always rejected.
        $hash = password_hash('0', PASSWORD_BCRYPT, ['cost' => 4]);

        self::assertFalse((new Password())->verify('0', $hash));
    }
}
