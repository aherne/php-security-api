<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\UnitTest\Result;
use Lucinda\UnitTest\Validator\Strings;

class RegenerationExceptionTest
{
    private RegenerationException $object;

    public function __construct()
    {
        $this->object = new RegenerationException();
    }

    public function setPayload()
    {
        $this->object->setPayload("asdfgh");
        return (new Strings($this->object->getPayload()))->assertEquals("asdfgh");
    }


    public function getPayload()
    {
        return (new Strings($this->object->getPayload()))->assertEquals("asdfgh");
    }
}
