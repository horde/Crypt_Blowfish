<?php

declare(strict_types=1);

namespace Horde\Crypt\Blowfish\Test;

use Horde_Crypt_Blowfish_Pbkdf2;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Horde_Crypt_Blowfish_Pbkdf2::class)]
class Pbkdf2Test extends TestCase
{
    #[DataProvider('vectorsProvider')]
    public function testVectors(
        string $expected,
        string $algo,
        string $pass,
        string $salt,
        int $iter,
        int $klen,
    ): void {
        $pbkdf2 = new Horde_Crypt_Blowfish_Pbkdf2($pass, $klen, [
            'algo' => $algo,
            'i_count' => $iter,
            'salt' => $salt,
        ]);

        $this->assertEquals(
            $expected,
            bin2hex((string) $pbkdf2)
        );

        $this->assertEquals(
            $algo,
            $pbkdf2->hashAlgo
        );

        $this->assertEquals(
            $iter,
            $pbkdf2->iterations
        );

        $this->assertEquals(
            $salt,
            $pbkdf2->salt
        );
    }

    public static function vectorsProvider(): array
    {
        return [
            /* Begin: RFC 6070 Vectors */
            [
                '0c60c80f961f0e71f3a9b524af6012062fe037a6',
                'SHA1',
                'password',
                'salt',
                1,
                20,
            ],
            [
                'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957',
                'SHA1',
                'password',
                'salt',
                2,
                20,
            ],
            [
                '4b007901b765489abead49d926f721d065a429c1',
                'SHA1',
                'password',
                'salt',
                4096,
                20,
            ],
            [
                '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
                'SHA1',
                'passwordPASSWORDpassword',
                'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                4096,
                25,
            ],
            [
                '56fa6aa75548099dcc37d7f03425e0c3',
                'SHA1',
                "pass\0word",
                "sa\0lt",
                4096,
                16,
            ],
            /* End: RFC 6070 Vectors */
            [
                '3144c39857011a14e27d2b83e6c814f8f3dab70208aa1b4ffab1b7978599ffc3',
                'SHA256',
                'Password Password',
                '123SaLt456',
                16384,
                32,
            ],
            [
                '0a866b26a368f733d2bd95dc0acea6b544c38ba31bc357f527cf85e9f6a937bb',
                'SHA512',
                'Password Password',
                '123SaLt456',
                16384,
                32,
            ],
        ];
    }

    public function testAutoSaltGeneration(): void
    {
        $pbkdf2 = new Horde_Crypt_Blowfish_Pbkdf2('password', 20);

        $this->assertEquals(
            20,
            strlen($pbkdf2->salt)
        );
    }
}
