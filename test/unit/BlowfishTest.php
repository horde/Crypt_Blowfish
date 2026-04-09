<?php

declare(strict_types=1);

namespace Horde\Crypt\Blowfish\Test;

use Horde\Crypt\Blowfish\Blowfish;
use Horde\Crypt\Blowfish\CipherMode;
use Horde\Crypt\Blowfish\EncryptionException;
use Horde\Crypt\Blowfish\InvalidKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Blowfish::class)]
class BlowfishTest extends TestCase
{
    public function testEcbRoundTrip(): void
    {
        $bf = Blowfish::ecb('secret_key');
        $plaintext = 'Hello, Blowfish!';

        $ciphertext = $bf->encrypt($plaintext);

        $this->assertNotSame($plaintext, $ciphertext);
        $this->assertSame($plaintext, $bf->decrypt($ciphertext));
    }

    public function testCbcRoundTripWithAutoIv(): void
    {
        $bf = Blowfish::cbc('secret_key');
        $iv = $bf->getIv();

        $this->assertSame(Blowfish::IV_LENGTH, strlen($iv));

        $plaintext = 'Hello, Blowfish CBC!';
        $ciphertext = $bf->encrypt($plaintext);

        // Decrypt with same key and IV
        $bf2 = Blowfish::cbc('secret_key', $iv);
        $this->assertSame($plaintext, $bf2->decrypt($ciphertext));
    }

    public function testCbcRoundTripWithExplicitIv(): void
    {
        $iv = str_repeat("\x01", 8);
        $bf = Blowfish::cbc('my_key_123', $iv);

        $this->assertSame($iv, $bf->getIv());

        $plaintext = 'Test data for CBC mode';
        $ciphertext = $bf->encrypt($plaintext);

        $bf2 = Blowfish::cbc('my_key_123', $iv);
        $this->assertSame($plaintext, $bf2->decrypt($ciphertext));
    }

    public function testEcbMode(): void
    {
        $this->assertSame(CipherMode::ECB, Blowfish::ecb('key123')->getMode());
    }

    public function testCbcMode(): void
    {
        $this->assertSame(CipherMode::CBC, Blowfish::cbc('key123')->getMode());
    }

    public function testEcbIvIsEmpty(): void
    {
        $this->assertSame('', Blowfish::ecb('key123')->getIv());
    }

    public function testEmptyKeyThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        Blowfish::ecb('');
    }

    public function testKeyTooLongThrows(): void
    {
        $this->expectException(InvalidKeyException::class);
        Blowfish::ecb(str_repeat('A', Blowfish::MAXKEYSIZE + 1));
    }

    public function testMaxLengthKeyWorks(): void
    {
        $key = str_repeat('A', Blowfish::MAXKEYSIZE);
        $bf = Blowfish::ecb($key);
        $plaintext = 'test';

        $this->assertSame($plaintext, $bf->decrypt($bf->encrypt($plaintext)));
    }

    public function testIvNormalizationTruncates(): void
    {
        $longIv = str_repeat('X', 16);
        $bf = Blowfish::cbc('key123', $longIv);

        $this->assertSame(Blowfish::IV_LENGTH, strlen($bf->getIv()));
        $this->assertSame(str_repeat('X', 8), $bf->getIv());
    }

    public function testIvNormalizationPads(): void
    {
        $shortIv = 'ABC';
        $bf = Blowfish::cbc('key123', $shortIv);

        $this->assertSame(Blowfish::IV_LENGTH, strlen($bf->getIv()));
        $this->assertSame("ABC\0\0\0\0\0", $bf->getIv());
    }

    public function testEmptyPlaintextRoundTrip(): void
    {
        $bf = Blowfish::ecb('secret');
        $plaintext = '';

        $this->assertSame($plaintext, $bf->decrypt($bf->encrypt($plaintext)));
    }

    public function testSingleByteRoundTrip(): void
    {
        $bf = Blowfish::ecb('secret');
        $plaintext = 'A';

        $this->assertSame($plaintext, $bf->decrypt($bf->encrypt($plaintext)));
    }

    public function testExactBlockSizeRoundTrip(): void
    {
        $bf = Blowfish::ecb('secret');
        // Exactly 8 bytes — PKCS#7 will add a full padding block
        $plaintext = '12345678';

        $ciphertext = $bf->encrypt($plaintext);
        // Should be 16 bytes: 8 data + 8 padding
        $this->assertSame(16, strlen($ciphertext));
        $this->assertSame($plaintext, $bf->decrypt($ciphertext));
    }

    public function testLargeDataRoundTrip(): void
    {
        $bf = Blowfish::cbc('long_key_test');
        $plaintext = str_repeat('The quick brown fox jumps. ', 100);

        $this->assertSame($plaintext, $bf->decrypt($bf->encrypt($plaintext)));
    }

    public function testDifferentKeysProduceDifferentCiphertext(): void
    {
        $plaintext = 'same plaintext';
        $iv = str_repeat("\0", 8);

        $ct1 = Blowfish::cbc('key_one!', $iv)->encrypt($plaintext);
        $ct2 = Blowfish::cbc('key_two!', $iv)->encrypt($plaintext);

        $this->assertNotSame($ct1, $ct2);
    }

    public function testDecryptWithWrongKeyFails(): void
    {
        $bf1 = Blowfish::ecb('correct_key');
        $ciphertext = $bf1->encrypt('secret data');

        $bf2 = Blowfish::ecb('wrong_key!!');

        $this->expectException(EncryptionException::class);
        $bf2->decrypt($ciphertext);
    }

    public function testDecryptCorruptedDataThrows(): void
    {
        $bf = Blowfish::ecb('my_key');

        // Random garbage that won't have valid PKCS#7 padding
        $this->expectException(EncryptionException::class);
        $bf->decrypt(random_bytes(16));
    }
}
