<?php

use Pebble\Security\Crypto;
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

    public function testSaltIsIgnoredWithoutWarning()
    {
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

        self::assertSame([], $warnings);
        self::assertStringStartsWith('$2y$04$', $hash);
        self::assertTrue(password_verify('x', $hash));
    }

    public function testPasswordIsADeprecatedFacadeOfCrypto()
    {
        $hash = Crypto::passwordHash('x', 4);

        self::assertTrue((new Password())->verify('x', $hash));
        self::assertTrue(Crypto::passwordVerify('x', (new Password())->setCost(4)->hash('x')));
    }

    public function testPasswordZeroVerifies()
    {
        $hash = (new Password())->setCost(4)->hash('0');

        self::assertTrue((new Password())->verify('0', $hash));
    }
}
