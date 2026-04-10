<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\Encryption;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;

class EncryptionTest
{
    private Encryption $object;
    private ?string $value = null;

    public function __construct()
    {
        $this->object = new Encryption((new SaltGenerator(12))->getSalt());
    }

    public function encrypt()
    {
        $this->value = $this->object->encrypt("asdfgh");
        return (new Strings($this->value))->assertNotEmpty();
    }


    public function decrypt()
    {
        return (new Strings($this->object->decrypt($this->value)))->assertEquals("asdfgh");
    }
}
