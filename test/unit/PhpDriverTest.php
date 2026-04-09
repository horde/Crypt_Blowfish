<?php

declare(strict_types=1);

namespace Horde\Crypt\Blowfish\Test;

use Horde\Crypt\Blowfish\CipherMode;
use Horde\Crypt\Blowfish\PhpDriver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(PhpDriver::class)]
class PhpDriverTest extends TestCase
{
    #[DataProvider('ecbVectorProvider')]
    public function testEcbRoundTrip(string $key, string $plaintext): void
    {
        $driver = new PhpDriver(CipherMode::ECB, $key, '');

        $ciphertext = $driver->encrypt($plaintext);

        $this->assertNotSame($plaintext, $ciphertext);
        $this->assertSame($plaintext, $driver->decrypt($ciphertext));
    }

    #[DataProvider('cbcVectorProvider')]
    public function testCbcRoundTrip(string $key, string $iv, string $plaintext): void
    {
        $driver = new PhpDriver(CipherMode::CBC, $key, $iv);

        $ciphertext = $driver->encrypt($plaintext);

        $this->assertNotSame($plaintext, $ciphertext);

        // Need a fresh driver for decryption (CBC state is consumed)
        $decryptDriver = new PhpDriver(CipherMode::CBC, $key, $iv);
        $this->assertSame($plaintext, $decryptDriver->decrypt($ciphertext));
    }

    public function testIsSupportedAlwaysTrue(): void
    {
        $this->assertTrue(PhpDriver::isSupported(CipherMode::ECB));
        $this->assertTrue(PhpDriver::isSupported(CipherMode::CBC));
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
