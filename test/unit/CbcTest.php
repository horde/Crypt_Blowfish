<?php

declare(strict_types=1);

namespace Horde\Crypt\Blowfish\Test;

use Horde_Crypt_Blowfish;
use Horde_Crypt_Blowfish_Mcrypt;
use Horde_Crypt_Blowfish_Openssl;
use Horde_Crypt_Blowfish_Php;
use Horde_Crypt_Blowfish_Php_Cbc;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Horde_Crypt_Blowfish::class)]
#[CoversClass(Horde_Crypt_Blowfish_Openssl::class)]
#[CoversClass(Horde_Crypt_Blowfish_Mcrypt::class)]
#[CoversClass(Horde_Crypt_Blowfish_Php::class)]
#[CoversClass(Horde_Crypt_Blowfish_Php_Cbc::class)]
class CbcTest extends TestCase
{
    #[DataProvider('vectorProvider')]
    public function testOpensslDriver(array $vector): void
    {
        if (!Horde_Crypt_Blowfish_Openssl::supported()) {
            $this->markTestSkipped('OpenSSL not available');
        }

        $ob = $this->setupTest($vector, 0);
        $encrypt = $ob->encrypt($vector['plain']);

        $this->assertNotEquals(
            $vector['plain'],
            $encrypt
        );

        $this->assertEquals(
            $vector['plain'],
            $ob->decrypt($encrypt)
        );
    }

    #[DataProvider('vectorProvider')]
    public function testMcryptDriver(array $vector): void
    {
        if (!Horde_Crypt_Blowfish_Mcrypt::supported()) {
            $this->markTestSkipped('Mcrypt not available');
        }

        $ob = $this->setupTest($vector, Horde_Crypt_Blowfish::IGNORE_OPENSSL);
        $encrypt = $ob->encrypt($vector['plain']);

        $this->assertNotEquals(
            $vector['plain'],
            $encrypt
        );

        $this->assertEquals(
            $vector['plain'],
            $ob->decrypt($encrypt)
        );
    }

    #[DataProvider('vectorProvider')]
    public function testPhpDriver(array $vector): void
    {
        $ob = $this->setupTest(
            $vector,
            Horde_Crypt_Blowfish::IGNORE_OPENSSL
            | Horde_Crypt_Blowfish::IGNORE_MCRYPT
        );
        $encrypt = $ob->encrypt($vector['plain']);

        $this->assertNotEquals(
            $vector['plain'],
            $encrypt
        );

        $this->assertEquals(
            $vector['plain'],
            $ob->decrypt($encrypt)
        );
    }

    public static function vectorProvider(): array
    {
        $data = file(__DIR__ . '/fixtures/vectors_cbc.txt');
        $vectors = [];

        foreach ($data as $val) {
            [$key, $iv, $plain] = explode(' ', trim($val));
            $vectors[] = [
                [
                    'key' => pack("H*", $key),
                    'iv' => pack("H*", $iv),
                    'plain' => pack("H*", $plain),
                ],
            ];
        }

        return $vectors;
    }

    protected function setupTest(array $v, int $ignore): Horde_Crypt_Blowfish
    {
        return new Horde_Crypt_Blowfish($v['key'], [
            'cipher' => 'cbc',
            'ignore' => $ignore,
            'iv' => $v['iv'],
        ]);
    }
}
