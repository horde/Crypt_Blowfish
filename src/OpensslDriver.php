<?php

declare(strict_types=1);

/**
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
 * OpenSSL-based Blowfish encryption driver.
 *
 * @internal Not part of the public API.
 *
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package  Crypt_Blowfish
 */
final class OpensslDriver implements DriverInterface
{
    private const CIPHER_PREFIX = 'bf-';

    private readonly string $cipherMethod;

    public function __construct(
        CipherMode $mode,
        private readonly string $key,
        private readonly string $iv,
    ) {
        $this->cipherMethod = self::CIPHER_PREFIX . $mode->value;
    }

    public function encrypt(string $plaintext): string
    {
        $result = openssl_encrypt(
            $plaintext,
            $this->cipherMethod,
            $this->key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->iv,
        );

        if ($result === false) {
            throw new EncryptionException(
                'OpenSSL encryption failed: ' . (openssl_error_string() ?: 'unknown error')
            );
        }

        return $result;
    }

    public function decrypt(string $ciphertext): string
    {
        $result = openssl_decrypt(
            $ciphertext,
            $this->cipherMethod,
            $this->key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->iv,
        );

        if ($result === false) {
            throw new EncryptionException(
                'OpenSSL decryption failed: ' . (openssl_error_string() ?: 'unknown error')
            );
        }

        return $result;
    }

    public static function isSupported(CipherMode $mode): bool
    {
        if (!extension_loaded('openssl')) {
            return false;
        }

        return in_array(
            self::CIPHER_PREFIX . $mode->value,
            openssl_get_cipher_methods(),
            true,
        );
    }
}
