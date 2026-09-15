<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Token\Encryption;

final class EncryptionTest
{
    public function encrypt()
    {
        $encrypted = (new Encryption("shared-secret"))->encrypt("sensitive payload");

        return (new Strings($encrypted))->assertNotEquals("sensitive payload");
    }

    public function decrypt()
    {
        $encryption = new Encryption("shared-secret");
        $encrypted = $encryption->encrypt("sensitive payload");
        $decrypted = $encryption->decrypt($encrypted);

        return (new Strings($decrypted))->assertEquals("sensitive payload");
    }
}
