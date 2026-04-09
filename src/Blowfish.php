<?php

declare(strict_types=1);

/**
 * Copyright 2005-2026 Matthew Fonda <mfonda@php.net>
 * Copyright 2012-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package  Crypt_Blowfish
 */

namespace Horde\Crypt\Blowfish;

/**
 * Immutable Blowfish encryption facade.
 *
 * Provides blowfish encryption/decryption for PHP strings with automatic
 * PKCS#7 padding and driver selection.
 *
 * Usage:
 *
 *     // ECB mode
 *     $bf = Blowfish::ecb($key);
 *     $ciphertext = $bf->encrypt($plaintext);
 *     $plaintext  = $bf->decrypt($ciphertext);
 *
 *     // CBC mode with auto-generated IV
 *     $bf = Blowfish::cbc($key);
 *     $iv = $bf->getIv();
 *
 *     // CBC mode with explicit IV
 *     $bf = Blowfish::cbc($key, $iv);
 *
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package  Crypt_Blowfish
 */
final class Blowfish
{
    public const BLOCKSIZE = 8;
    public const MAXKEYSIZE = 56;
    public const IV_LENGTH = 8;

    private readonly DriverInterface $driver;

    private function __construct(
        private readonly CipherMode $mode,
        string $key,
        private readonly string $iv,
    ) {
        $this->driver = self::selectDriver($mode, $key, $iv);
    }

    /**
     * Create an ECB-mode Blowfish instance.
     *
     * @throws InvalidKeyException If key is empty or exceeds 56 bytes
     */
    public static function ecb(string $key): self
    {
        self::validateKey($key);

        return new self(CipherMode::ECB, $key, '');
    }

    /**
     * Create a CBC-mode Blowfish instance.
     *
     * If no IV is provided, a cryptographically random one is generated.
     * A provided IV is normalized to exactly 8 bytes (truncated or zero-padded).
     *
     * @throws InvalidKeyException If key is empty or exceeds 56 bytes
     */
    public static function cbc(string $key, ?string $iv = null): self
    {
        self::validateKey($key);

        if ($iv === null) {
            $iv = random_bytes(self::IV_LENGTH);
        } else {
            $iv = self::normalizeIv($iv);
        }

        return new self(CipherMode::CBC, $key, $iv);
    }

    /**
     * Encrypt a plaintext string.
     *
     * PKCS#7 padding is applied automatically.
     *
     * @throws EncryptionException If encryption fails
     */
    public function encrypt(string $plaintext): string
    {
        return $this->driver->encrypt(self::pad($plaintext));
    }

    /**
     * Decrypt a ciphertext string.
     *
     * PKCS#7 padding is removed automatically.
     *
     * @throws EncryptionException If decryption fails or padding is invalid
     */
    public function decrypt(string $ciphertext): string
    {
        return self::unpad($this->driver->decrypt($ciphertext));
    }

    /**
     * Return the initialization vector.
     *
     * Returns an empty string for ECB mode.
     */
    public function getIv(): string
    {
        return $this->iv;
    }

    public function getMode(): CipherMode
    {
        return $this->mode;
    }

    private static function validateKey(string $key): void
    {
        $length = strlen($key);

        if ($length === 0) {
            throw new InvalidKeyException('Encryption key must not be empty.');
        }

        if ($length > self::MAXKEYSIZE) {
            throw new InvalidKeyException(
                sprintf(
                    'Encryption key must not exceed %d bytes. Supplied key length: %d',
                    self::MAXKEYSIZE,
                    $length,
                )
            );
        }
    }

    /**
     * Normalize an IV to exactly IV_LENGTH bytes.
     *
     * Truncates if too long, zero-pads if too short.
     */
    private static function normalizeIv(string $iv): string
    {
        $iv = substr($iv, 0, self::IV_LENGTH);
        $length = strlen($iv);

        if ($length < self::IV_LENGTH) {
            $iv .= str_repeat("\0", self::IV_LENGTH - $length);
        }

        return $iv;
    }

    private static function selectDriver(CipherMode $mode, string $key, string $iv): DriverInterface
    {
        if (OpensslDriver::isSupported($mode)) {
            return new OpensslDriver($mode, $key, $iv);
        }

        return new PhpDriver($mode, $key, $iv);
    }

    /**
     * Apply PKCS#7 padding to the given data.
     */
    private static function pad(string $data): string
    {
        $padLength = self::BLOCKSIZE - (strlen($data) % self::BLOCKSIZE);

        return $data . str_repeat(chr($padLength), $padLength);
    }

    /**
     * Remove and validate PKCS#7 padding from decrypted data.
     *
     * @throws EncryptionException If padding is invalid
     */
    private static function unpad(string $data): string
    {
        $length = strlen($data);

        if ($length === 0) {
            throw new EncryptionException('Decrypted data is empty; cannot remove padding.');
        }

        $padByte = ord($data[$length - 1]);

        if ($padByte < 1 || $padByte > self::BLOCKSIZE) {
            throw new EncryptionException(
                sprintf('Invalid PKCS#7 padding byte: 0x%02X', $padByte)
            );
        }

        if ($padByte > $length) {
            throw new EncryptionException('Padding length exceeds data length.');
        }

        // Verify all padding bytes are consistent.
        $padding = substr($data, $length - $padByte);

        if ($padding !== str_repeat(chr($padByte), $padByte)) {
            throw new EncryptionException('Inconsistent PKCS#7 padding bytes.');
        }

        return substr($data, 0, $length - $padByte);
    }
}
