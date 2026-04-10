<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;

class SynchronizerTokenTest
{
    private SynchronizerToken $object;
    private ?string $value = null;

    public function __construct()
    {
        $this->object = new SynchronizerToken("127.0.0.1", (new SaltGenerator(12))->getSalt());
    }

    public function encode()
    {
        $this->value = $this->object->encode(1);
        return (new Strings($this->value))->assertNotEmpty();
    }


    public function decode()
    {
        return (new Integers((int) $this->object->decode($this->value)))->assertEquals(1);
    }
}
