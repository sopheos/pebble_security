<?php

use Pebble\Security\Hash;
use PHPUnit\Framework\TestCase;

class HashTest extends TestCase
{
    // -------------------------------------------------------------------------
    // make / salt / random
    // -------------------------------------------------------------------------

    public function testMakePicksTheAlgorithmFromTheLength()
    {
        self::assertSame(md5('x'), Hash::make('x', 32));
        self::assertSame(sha1('x'), Hash::make('x'));
        self::assertSame(hash('sha256', 'x'), Hash::make('x', 64));
        self::assertSame(128, strlen(Hash::make('x', 128)));
    }

    public function testMakeFallsBackToSha1ForUnknownLengths()
    {
        self::assertSame(sha1('x'), Hash::make('x', 12));
    }

    public function testSaltLengthFollowsTheSameFallback()
    {
        self::assertSame(64, strlen(Hash::salt(64)));
        self::assertSame(40, strlen(Hash::salt(10)));
    }

    public function testRandomReturnsHexOfTheRequestedLength()
    {
        self::assertMatchesRegularExpression('/^[0-9a-f]{7}$/', Hash::random(7));
        self::assertNotSame(Hash::random(), Hash::random());
    }

    // -------------------------------------------------------------------------
    // otp / email
    // -------------------------------------------------------------------------

    public function testOtpIsZeroPaddedDigits()
    {
        self::assertMatchesRegularExpression('/^[0-9]{6}$/', Hash::otp());
        self::assertMatchesRegularExpression('/^[0-9]{4}$/', Hash::otp(4));
    }

    public function testEmailHashesNameAndDomainButKeepsTheTld()
    {
        self::assertSame(sha1('john') . '@' . sha1('mail.co') . '.uk', Hash::email('john@mail.co.uk'));
        self::assertNull(Hash::email('not-an-email'));
    }

    // -------------------------------------------------------------------------
    // Known bugs (see TODO.md)
    // -------------------------------------------------------------------------

    public function testOtpUsesMtRand()
    {
        // BUG: otp() uses mt_rand(), which is seedable and predictable.
        mt_srand(42);
        $first = Hash::otp();
        mt_srand(42);
        $second = Hash::otp();
        mt_srand();

        self::assertSame($first, $second);
    }

    public function testUuidStartsWithTheUniqidTimestamp()
    {
        // BUG: uuid() is built on uniqid(); the first 8 hex digits are the Unix time.
        $before = time();
        $uuid = Hash::uuid();
        $after = time();

        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $uuid);
        self::assertGreaterThanOrEqual($before, hexdec(substr($uuid, 0, 8)));
        self::assertLessThanOrEqual($after, hexdec(substr($uuid, 0, 8)));
    }

    public function testUuidVersionCharacterIsNotAlways4()
    {
        // BUG: no RFC 4122 version/variant bits are set; the version slot holds a uniqid digit.
        $versions = [];
        for ($i = 0; $i < 64; $i++) {
            $versions[Hash::uuid()[14]] = true;
            usleep(1);
        }

        self::assertGreaterThan(1, count($versions));
    }
}
