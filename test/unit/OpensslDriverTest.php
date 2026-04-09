<?php

declare(strict_types=1);

namespace Horde\Crypt\Blowfish\Test;

use Horde\Crypt\Blowfish\CipherMode;
use Horde\Crypt\Blowfish\OpensslDriver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(OpensslDriver::class)]
class OpensslDriverTest extends TestCase
{
    #[DataProvider('ecbVectorProvider')]
    public function testEcbRoundTrip(string $key, string $plaintext): void
    {
        if (!OpensslDriver::isSupported(CipherMode::ECB)) {
            $this->markTestSkipped('OpenSSL bf-ecb not available');
        }

        $driver = new OpensslDriver(CipherMode::ECB, $key, '');

        $ciphertext = $driver->encrypt($plaintext);

        $this->assertNotSame($plaintext, $ciphertext);
        $this->assertSame($plaintext, $driver->decrypt($ciphertext));
    }

    #[DataProvider('cbcVectorProvider')]
    public function testCbcRoundTrip(string $key, string $iv, string $plaintext): void
    {
        if (!OpensslDriver::isSupported(CipherMode::CBC)) {
            $this->markTestSkipped('OpenSSL bf-cbc not available');
        }

        $driver = new OpensslDriver(CipherMode::CBC, $key, $iv);

        $ciphertext = $driver->encrypt($plaintext);

        $this->assertNotSame($plaintext, $ciphertext);
        $this->assertSame($plaintext, $driver->decrypt($ciphertext));
    }

    public static function ecbVectorProvider(): array
    {
        $data = file(__DIR__ . '/fixtures/vectors.txt');
        $vectors = [];

        foreach ($data as $val) {
            $val = trim($val);
            if ($val === '') {
                continue;
            }
            [$key, $plain] = explode(' ', $val);
            $plainBytes = pack('H*', $plain);
            // Driver expects pre-padded input (multiple of 8 bytes)
            if (strlen($plainBytes) % 8 !== 0) {
                continue;
            }
            $vectors[] = [
                pack('H*', $key),
                $plainBytes,
            ];
        }

        return $vectors;
    }

    public static function cbcVectorProvider(): array
    {
        $data = file(__DIR__ . '/fixtures/vectors_cbc.txt');
        $vectors = [];

        foreach ($data as $val) {
            $val = trim($val);
            if ($val === '') {
                continue;
            }
            [$key, $iv, $plain] = explode(' ', $val);
            $vectors[] = [
                pack('H*', $key),
                pack('H*', $iv),
                pack('H*', $plain),
            ];
        }

        return $vectors;
    }
}
