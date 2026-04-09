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
 * Internal driver interface for Blowfish encryption backends.
 *
 * Drivers operate on pre-padded plaintext and return raw ciphertext.
 * PKCS#7 padding is handled by the Blowfish facade, not the drivers.
 *
 * @internal Not part of the public API.
 *
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package  Crypt_Blowfish
 */
interface DriverInterface
{
    /**
     * Encrypt pre-padded plaintext.
     *
     * Input MUST be padded to 8-byte boundary before calling.
     *
     * @throws EncryptionException If encryption fails
     */
    public function encrypt(string $plaintext): string;

    /**
     * Decrypt ciphertext.
     *
     * Returns raw decrypted data including padding bytes.
     *
     * @throws EncryptionException If decryption fails
     */
    public function decrypt(string $ciphertext): string;

    /**
     * Check if this driver is available for the given cipher mode.
     */
    public static function isSupported(CipherMode $mode): bool;
}
