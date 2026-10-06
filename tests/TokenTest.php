<?php

use Pebble\Security\JWT;
use Pebble\Security\Token;
use Pebble\Security\TokenException;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    private function token(?string $proof = null): Token
    {
        return new Token('https://api.example', 'secret', JWT::HS256, $proof);
    }

    // -------------------------------------------------------------------------
    // Nominal
    // -------------------------------------------------------------------------

    public function testConstructorInitialisesUuidAndProofHash()
    {
        $token = $this->token('device-1');

        self::assertSame(36, strlen($token->uuid()));
        self::assertSame(sha1('device-1'), $token->hash());
        self::assertSame(['uuid' => $token->uuid(), 'hash' => sha1('device-1')], $token->payload());
    }

    public function testGenerateAndImportRoundTrip()
    {
        $source = $this->token('device-1')->add('id', 5);
        $jwt = $source->generate(60);

        $imported = $this->token('device-1')->import('Bearer ' . $jwt);

        self::assertSame(5, $imported->get('id'));
        self::assertSame($source->uuid(), $imported->uuid());
        self::assertSame($imported->get('iat') + 60, $imported->get('exp'));
    }

    public function testAddNullRemovesAKey()
    {
        $token = $this->token()->add('a', 1)->del('a')->add('b', null);

        self::assertNull($token->get('a'));
        self::assertSame('x', $token->get('b', 'x'));
        self::assertArrayNotHasKey('hash', $token->payload());
    }

    public function testEmptyTokenIsRequired()
    {
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('token_required');
        $this->token()->import('');
    }

    public function testAnyDecodeErrorBecomesTokenInvalid()
    {
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('token_invalid');
        $this->token()->import('a.b.c');
    }

    public function testTokenWithAnotherAlgorithmIsRejected()
    {
        $jwt = JWT::encode(['uuid' => 'u'], 'secret', JWT::HS512);

        $this->expectExceptionMessage('token_invalid');
        $this->token()->import($jwt);
    }

    public function testProofMismatchIsRejected()
    {
        $jwt = $this->token('device-1')->generate();

        $this->expectExceptionMessage('token_invalid');
        $this->token('device-2')->import($jwt);
    }

    public function testImporterWithoutProofAcceptsAnyHashAndDropsIt()
    {
        $jwt = $this->token('device-1')->generate();
        $imported = $this->token()->import($jwt);

        self::assertArrayHasKey('uuid', $imported->payload());
        self::assertNull($imported->get('hash'));
    }

    public function testParseTokenStripsBearer()
    {
        self::assertSame('a.b.c', Token::parseToken('bearer a.b.c'));
        self::assertSame('raw', Token::parseToken('raw'));
    }
}
