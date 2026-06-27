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

use RuntimeException;

/**
 * Exception for encryption/decryption failures.
 *
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package  Crypt_Blowfish
 */
class EncryptionException extends RuntimeException {}
