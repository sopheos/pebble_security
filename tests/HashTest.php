<?php

use Pebble\Security\Crypto;
use Pebble\Security\Hash;
use PHPUnit\Framework\TestCase;

class HashTest extends TestCase
{
    // -------------------------------------------------------------------------
    // hash / salt / random
    // -------------------------------------------------------------------------

    public function testHashPicksTheAlgorithmFromTheLength()
    {
        self::assertSame(md5('x'), Crypto::hash('x', 32));
        self::assertSame(sha1('x'), Crypto::hash('x'));
        self::assertSame(hash('sha256', 'x'), Crypto::hash('x', 64));
        self::assertSame(128, strlen(Crypto::hash('x', 128)));
    }

    public function testHashFallsBackToSha1ForUnknownLengths()
    {
        self::assertSame(sha1('x'), Crypto::hash('x', 12));
    }

    public function testSaltLengthFollowsTheSameFallback()
    {
        self::assertSame(64, strlen(Crypto::salt(64)));
        self::assertSame(40, strlen(Crypto::salt(10)));
    }

    public function testRandomReturnsHexOfTheRequestedLength()
    {
        self::assertMatchesRegularExpression('/^[0-9a-f]{7}$/', Crypto::random(7));
        self::assertNotSame(Crypto::random(), Crypto::random());
    }

    // -------------------------------------------------------------------------
    // uuid / otp / email
    // -------------------------------------------------------------------------

    public function testUuidIsAnRfc9562Version7()
    {
        $uuid = Crypto::uuid();

        self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $uuid);
    }

    public function testUuidStartsWithTheMillisecondTimestamp()
    {
        $before = (int) (microtime(true) * 1000);
        $uuid = Crypto::uuid();
        $after = (int) (microtime(true) * 1000);

        $ms = hexdec(substr($uuid, 0, 8) . substr($uuid, 9, 4));

        self::assertGreaterThanOrEqual($before, $ms);
        self::assertLessThanOrEqual($after, $ms);
    }

    public function testOtpIsZeroPaddedDigits()
    {
        self::assertMatchesRegularExpression('/^[0-9]{6}$/', Crypto::otp());
        self::assertMatchesRegularExpression('/^[0-9]{4}$/', Crypto::otp(4));
    }

    public function testOtpIsNotSeededByMtSrand()
    {
        $codes = [];
        for ($i = 0; $i < 5; $i++) {
            mt_srand(42);
            $codes[Crypto::otp(18)] = true;
        }
        mt_srand();

        self::assertGreaterThan(1, count($codes));
    }

    public function testOtpRejectsOutOfRangeLengths()
    {
        $this->expectException(\ValueError::class);

        Crypto::otp(19);
    }

    public function testEmailHashesNameAndDomainButKeepsTheTld()
    {
        self::assertSame(sha1('john') . '@' . sha1('mail.co') . '.uk', Crypto::email('john@mail.co.uk'));
        self::assertNull(Crypto::email('not-an-email'));
    }

    // -------------------------------------------------------------------------
    // Deprecated Hash facade
    // -------------------------------------------------------------------------

    public function testHashIsADeprecatedFacadeOfCrypto()
    {
        self::assertNotInstanceOf(Crypto::class, new Hash());
        self::assertStringContainsString('@deprecated', (new ReflectionClass(Hash::class))->getDocComment());

        foreach ((new ReflectionClass(Hash::class))->getMethods() as $method) {
            self::assertStringContainsString('@deprecated', $method->getDocComment(), $method->getName());
        }
    }

    public function testHashMakeStillReturnsAHash()
    {
        self::assertSame(sha1('x'), Hash::make('x'));
        self::assertSame(md5('x'), Hash::make('x', 32));
    }

    public function testHashStaticHelpersDelegateToCrypto()
    {
        self::assertSame(40, strlen(Hash::salt()));
        self::assertSame(7, strlen(Hash::random(7)));
        self::assertSame(36, strlen(Hash::uuid()));
        self::assertSame(6, strlen(Hash::otp()));
        self::assertSame(Crypto::email('a@b.fr'), Hash::email('a@b.fr'));
    }
}
