<?php

declare(strict_types=1);

namespace Horde\Crypt\Blowfish\Test;

use Horde\Crypt\Blowfish\CipherMode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CipherMode::class)]
class CipherModeTest extends TestCase
{
    public function testEcbValue(): void
    {
        $this->assertSame('ecb', CipherMode::ECB->value);
    }

    public function testCbcValue(): void
    {
        $this->assertSame('cbc', CipherMode::CBC->value);
    }

    public function testFromEcb(): void
    {
        $this->assertSame(CipherMode::ECB, CipherMode::from('ecb'));
    }

    public function testFromCbc(): void
    {
        $this->assertSame(CipherMode::CBC, CipherMode::from('cbc'));
    }

    public function testFromInvalid(): void
    {
        $this->expectException(\ValueError::class);
        CipherMode::from('cfb');
    }
}
