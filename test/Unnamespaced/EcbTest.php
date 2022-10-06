<?php
/**
 * @category   Horde
 * @package    Crypt_Blowfish
 * @subpackage UnitTests
 */
namespace Horde\Crypt\Blowfish\Test;
use Horde_Test_Case;
use \Horde_Crypt_Blowfish;
use \Horde_Crypt_Blowfish_Mcrypt;
use \Horde_Crypt_Blowfish_Openssl;

/**
 * @category   Horde
 * @package    Crypt_Blowfish
 * @subpackage UnitTests
 */
class EcbTest extends Horde_Test_Case
{
    /**
     * @dataProvider vectorProvider
     */
    public function testOpensslDriver($vector)
    {
        if (!Horde_Crypt_Blowfish_Openssl::supported()) {
            $this->markTestSkipped();
        }

        $ob = $this->setupTest($vector, 0);
        $encrypt = $ob->encrypt($vector['plain']);

        // Let's verify some sort of obfuscation occurred.
        $this->assertNotEquals(
            $vector['plain'],
            $encrypt
        );

        $this->assertEquals(
            $vector['plain'],
            $ob->decrypt($encrypt)
        );

    }

    /**
     * @dataProvider vectorProvider
     */
    public function testMcryptDriver($vector)
    {
        if (!Horde_Crypt_Blowfish_Mcrypt::supported()) {
            $this->markTestSkipped();
        }

        $ob = $this->setupTest($vector, Horde_Crypt_Blowfish::IGNORE_OPENSSL);
        $encrypt = $ob->encrypt($vector['plain']);

        // Let's verify some sort of obfuscation occurred.
        $this->assertNotEquals(
            $vector['plain'],
            $encrypt
        );

        $this->assertEquals(
            $vector['plain'],
            $ob->decrypt($encrypt)
        );

    }

    /**
     * @dataProvider vectorProvider
     */
    public function testPhpDriver($vector)
    {
        $ob = $this->setupTest(
            $vector,
            Horde_Crypt_Blowfish::IGNORE_OPENSSL |
            Horde_Crypt_Blowfish::IGNORE_MCRYPT
        );
        $encrypt = $ob->encrypt($vector['plain']);

        // Let's verify some sort of obfuscation occurred.
        $this->assertNotEquals(
            $vector['plain'],
            $encrypt
        );

        $this->assertEquals(
            $vector['plain'],
            $ob->decrypt($encrypt)
        );

    }

    public function vectorProvider()
    {
        $data = file(dirname(__FILE__) . '/fixtures/vectors.txt');
        $vectors = array();

        foreach ($data as $val) {
            list($key, $plain) = explode(' ', trim($val));
            $vectors[] = array(
                array(
                    'key' => pack("H*", $key),
                    'plain' => pack("H*", $plain)
                )
            );
        }

        return $vectors;
    }

    protected function setupTest($v, $ignore)
    {
        return new Horde_Crypt_Blowfish($v['key'], array(
            'cipher' => 'ecb',
            'ignore' => $ignore
        ));
    }
}
